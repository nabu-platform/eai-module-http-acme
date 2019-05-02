package nabu.protocols.http.acme;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.URI;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.annotation.XmlRootElement;

import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.nabu.eai.module.http.acme.AcmeArtifact;
import be.nabu.eai.module.http.virtual.VirtualHostArtifact;
import be.nabu.eai.module.keystore.KeyStoreArtifact;
import be.nabu.eai.repository.EAIResourceRepository;
import be.nabu.eai.repository.api.ClusteredServer;
import be.nabu.libs.cluster.api.ClusterInstance;
import be.nabu.libs.cluster.api.ClusterLock;
import be.nabu.libs.cluster.api.ClusterMap;
import be.nabu.utils.security.BCSecurityUtils;
import be.nabu.utils.security.KeyPairType;
import be.nabu.utils.security.KeyStoreHandler;
import be.nabu.utils.security.SecurityUtils;
import be.nabu.utils.security.SignatureType;
import be.nabu.utils.security.StoreType;

@WebService
public class Services {
	
	
	public static class VerificationResult {
		private X509Certificate certificate;

		public X509Certificate getCertificate() {
			return certificate;
		}

		public void setCertificate(X509Certificate certificate) {
			this.certificate = certificate;
		}
	}
	
	private Logger logger = LoggerFactory.getLogger(getClass());
	
	// can verify for a single acme, for a group of acme or all acme
	// we can do this with a startup service that scans every 12 hours or so
	@WebResult(name = "verification")
	public void verifyCertificate(@WebParam(name = "acmeId") String acmeId, @WebParam(name = "staging") Boolean staging, @WebParam(name = "timeout") Long timeout, @WebParam(name = "persist") Boolean persist, @WebParam(name = "force") Boolean force) {
		for (AcmeArtifact acme : EAIResourceRepository.getInstance().getArtifacts(AcmeArtifact.class)) {
			if (acmeId == null || acme.getId().equals(acmeId) || acme.getId().startsWith(acmeId + ".")) {
				if (persist == null) {
					persist = EAIResourceRepository.isDevelopment() || Boolean.parseBoolean(System.getProperty("acme.persist", "false"));
				}
				if (staging == null) {
					staging = EAIResourceRepository.isDevelopment() || Boolean.parseBoolean(System.getProperty("acme.staging", "false"));
				}
				// we default to 1 minute
				verifyCertificate(acme, staging != null && staging, timeout == null ? 1000l * 60 * 60 : timeout, persist, force != null && force);
			}
		}
	}
	
	private VerificationResult verifyCertificate(AcmeArtifact artifact, boolean staging, long timeout, boolean persist, boolean force) {
		// if there is no certificate, check the shared map to see if someone in the cluster already requested one
		X509Certificate validCertificate = null;
		try {
			// we are only interested in hosts that have an alias linked to a server that has a keystore
			if (artifact.getConfig().isEnabled() && artifact.getRepository().getServiceRunner() instanceof ClusteredServer && artifact.getConfig().getVirtualHost() != null && artifact.getConfig().getVirtualHost().getConfig().getKeyAlias() != null && artifact.getConfig().getVirtualHost().getConfig().getServer().getConfig().getKeystore() != null) {
				logger.info("[{}] Verifying ACME certificate", artifact.getId());
				
				ClusterInstance cluster = ((ClusteredServer) artifact.getRepository().getServiceRunner()).getCluster();
				KeyStoreArtifact keystore = artifact.getConfig().getVirtualHost().getConfig().getServer().getConfig().getKeystore();
				String keyAlias = artifact.getConfig().getVirtualHost().getConfig().getKeyAlias();
				String acmeAlias = "acme2-" + artifact.getId();
				VirtualHostArtifact virtualHost = artifact.getConfig().getVirtualHost();
				
				// if there is no entry yet, we need to refresh
				// if there is an entry but it expires in less than 3 days, we want to refresh as well
				boolean refresh = true;
				
				KeyPair serverKeyPair = null;
				PrivateKey privateKey = keystore.getKeyStore().getPrivateKey(acmeAlias);
				if (privateKey != null && !force) {
					X509Certificate x509Certificate = keystore.getKeyStore().getChain(acmeAlias)[0];
					// if the certificate is valid for at least 3 more days, we don't need to refresh
					if (x509Certificate.getNotAfter().after(new Date(new Date().getTime() + 1000l*60*60*24*3))) {
						refresh = false;
						logger.info("[{}] Existing certificate for " + virtualHost.getConfig().getHost() + " valid until: " + x509Certificate.getNotAfter(), artifact.getId());
						validCertificate = x509Certificate;
					}
					else {
						logger.info("[{}] Certificate for " + virtualHost.getConfig().getHost() + " expires at: " + x509Certificate.getNotAfter(), artifact.getId());
					}
				}
				
				// if we already have a private key pair in the keystore, use that
				if (privateKey != null) {
					serverKeyPair = new KeyPair(
						keystore.getKeyStore().getChain(acmeAlias)[0].getPublicKey(),
						privateKey
					);
				}
				
				if (refresh) {
					logger.info("[{}] Refreshing ACME certificate (force: " + force + ")", artifact.getId());
					
					// get a cluster lock
					ClusterLock lock = cluster.lock(artifact.getId() + ":acme-lock");
					
					logger.info("[{}] Acquiring ACME lock", artifact.getId());
					// a blocking lock, only one server at a time should do this
					lock.lock();
					try {
						logger.info("[{}] ACME lock acquired, checking map for valid ACME certificate", artifact.getId());
						ClusterMap<Object, Object> map = cluster.map(artifact.getId() + ":acme");
						
						Object object = map.get("pkcs12");
						// if we want to force a renegotiation, don't try to load from the map
						if (object instanceof byte[] && !force) {
							KeyStoreHandler toMerge = KeyStoreHandler.load(new ByteArrayInputStream((byte[]) object), artifact.getId(), StoreType.PKCS12);
							X509Certificate[] chain = toMerge.getPrivateKeys().get(acmeAlias);
							if (chain != null && chain.length > 0) {
								serverKeyPair = new KeyPair(
									chain[0].getPublicKey(),
									toMerge.getPrivateKey(acmeAlias, null)
								);
								X509Certificate x509Certificate = chain[0];
								// if it is valid for more than 6 days, use it
								if (x509Certificate.getNotAfter().after(new Date(new Date().getTime() + 1000l*60*60*24*6))) {
									logger.info("[{}] Found certificate in clustered map that is valid until: " + x509Certificate.getNotAfter(), artifact.getId());
									refresh = false;
									validCertificate = x509Certificate;
									// this makes sure the "new" keystore gets loaded, activated and saved
									artifact.releaseAllSubscriptions((byte []) object);
								}
								else {
									logger.info("[{}] Found certificate but it expires at: " + x509Certificate.getNotAfter(), artifact.getId());
								}
							}
						}
						else if (object instanceof byte[] && force) {
							logger.info("[{}] Entry found in the clustered map but forcibly refreshing", artifact.getId());
						}
						else {
							logger.info("[{}] No entry in the clustered map", artifact.getId());	
						}

						// need to actually call acme
						if (refresh) {
							logger.info("[{}] Starting ACME exchange", artifact.getId());
							// the keypair we have already (presumably selfsigned) serves as the user credentials
							X509Certificate userCertificate = keystore.getKeyStore().getChain(keyAlias)[0];
							KeyPair user = new KeyPair(
								userCertificate.getPublicKey(),
								keystore.getKeyStore().getPrivateKey(keyAlias)
							);
							
							logger.info("[{}] Creating session (staging: " + staging + ")", artifact.getId());
							Session session = new Session(staging ? "acme://letsencrypt.org/staging" : "acme://letsencrypt.org");
							
							URI tos = session.getMetadata().getTermsOfService();
							logger.info("[{}] Creating account (terms of service: " + tos + ")", artifact.getId());
							
							Account account = new AccountBuilder()
								.agreeToTermsOfService()
								.useKeyPair(user)
								.create(session);
							
							// if we reuse the existing keypair we get:
							// Error finalizing order :: certificate public key must be different than account key
							logger.info("[{}] Generating new keypair (RSA 4096)", artifact.getId());
							serverKeyPair = SecurityUtils.generateKeyPair(KeyPairType.RSA, 4096);
							
							List<String> domains = new ArrayList<String>();
							// add the main domain
							domains.add(virtualHost.getConfig().getHost());
							// add all aliases
							if (virtualHost.getConfig().getAliases() != null) {
								domains.addAll(virtualHost.getConfig().getAliases());
							}
							// check for each domain that it is not local
							Iterator<String> it = domains.iterator();
							while (it.hasNext()) {
								String domain = it.next();
								try {
									InetAddress byName = InetAddress.getByName(domain);
									// they can be different in case of CNAME's
									// the problem is that we often use CNAME to reference non-prd amazon servers
									// however, amazon will resolve a DNS request for a server from within the amazon infrastructure to a local ip and if you query it from outside of amazon to an external ip
									// this is a rather nasty hack to make sure that if we are using CNAME's, we assume it is approachable from the outside...
									// so when using ACME resolving on CNAME's that point to actually unavailable internal ips, this will fail...
									// quite possibly the signing will still go through correctly just not include the host (which would be acceptable behavior), otherwise we might have to revisit this...
									if (!byName.getHostName().equals(byName.getCanonicalHostName())) {
										continue;
									}
									if (byName.isAnyLocalAddress() || byName.isLinkLocalAddress() || byName.isLoopbackAddress() || byName.isSiteLocalAddress()) {
										logger.warn("Skipping local domain: " + domain);
										it.remove();
									}
								}
								catch (Exception e) {
									logger.warn("Skipping unresolvable domain: " + domain, e);
									it.remove();
								}
							}
							
							logger.info("[{}] Creating order for: " + domains, artifact.getId());
							Order order = account.newOrder().domains(domains).create();
							
							List<Challenge> challenges = new ArrayList<Challenge>();
							byte [] pkcs12 = null;
							// we add subscriptions for all domains
							try {
								for (Authorization authorization : order.getAuthorizations()) {
									Http01Challenge httpChallenge = authorization.findChallenge(Http01Challenge.TYPE);
									if (httpChallenge == null) {
										logger.error("[{}] No http challenge found for authorization of: " + authorization.getDomain(), artifact.getId());
										throw new IllegalStateException("Could not find http challenge for domain: " + authorization.getDomain());
									}
									logger.info("[{}] Adding subscription for: " + authorization.getDomain(), artifact.getId());
									artifact.subscribe(httpChallenge.getToken(), httpChallenge.getAuthorization());
									challenges.add(httpChallenge);
								}
								
								
								// we trigger all the challenges
								for (Challenge challenge : challenges) {
									challenge.trigger();
								}
								
								// we start the polling for successfull completion of all the challenges
								Date started = new Date();
								logger.info("[{}] Starting challenge validation", artifact.getId());
								while (!challenges.isEmpty() && new Date().getTime() < started.getTime() + timeout) {
									for (Challenge challenge : challenges) {
										if (challenge.getStatus() == Status.INVALID) {
											logger.error("[{}] Invalid challenge found: " + challenge.getError(), artifact.getId());
											throw new IllegalStateException("The challenge is invalid: " + challenge.getError());
										}
									}
									// we sleep to give the ACME server some time to do the polling
									Thread.sleep(3000L);
									
									Iterator<Challenge> iterator = challenges.iterator();
									while (iterator.hasNext()) {
										Challenge challenge = iterator.next();
										challenge.update();
										if (challenge.getStatus() == Status.VALID) {
											logger.info("[{}] Validated challenge", artifact.getId());
											iterator.remove();
										}
									}
								}
								
								if (!challenges.isEmpty()) {
									for (Challenge challenge : challenges) {
										logger.error("[{}] Could not validate challenge (" + challenge.getStatus() + "): " + challenge.getError(), artifact.getId());
									}
									throw new IllegalStateException("Could not validate all challenges, " + challenges.size() + " remaining");
								}
								
								List<String> alternateDomains = new ArrayList<String>(domains);
								domains.remove(virtualHost.getConfig().getHost());
								
								Map<String, String> parts = SecurityUtils.getParts(userCertificate.getSubjectX500Principal());
								X500Principal principal = SecurityUtils.createX500Principal(virtualHost.getConfig().getHost(), parts.get("O"), parts.get("OU"), parts.get("L"), parts.get("ST"), parts.get("C"));
								
								logger.info("[{}] Generating PKCS10 for principal: " + principal, artifact.getId());
								byte[] pkcs10 = BCSecurityUtils.generatePKCS10(
									serverKeyPair, 
									SignatureType.SHA256WITHRSA, 
									principal, 
									alternateDomains.toArray(new String[0])
								);
								
								logger.info("[{}] Executing order", artifact.getId());
								order.execute(pkcs10);
								
								started = new Date();
								while (order.getStatus() != Status.VALID && new Date().getTime() < started.getTime() + timeout) {
									if (order.getStatus() == Status.INVALID) {
										logger.error("[{}] Invalid order: " + order.getError(), artifact.getId());
										throw new IllegalStateException("The order is invalid: " + order.getError());
									}
									Thread.sleep(3000L);
									order.update();
								}
								
								if (order.getStatus() != Status.VALID) {
									logger.error("[{}] Invalid order: " + order.getError(), artifact.getId());
									throw new IllegalStateException("The order is invalid: " + order.getError());
								}
								else {
									logger.info("[{}] Order successful", artifact.getId());
								}
								
								Certificate certificate = order.getCertificate();
								
								// we are interested in the current certificate
								validCertificate = certificate.getCertificateChain().get(0);
								
								// create a new key store to persist it
								KeyStoreHandler temporary = KeyStoreHandler.create(artifact.getId(), StoreType.PKCS12);
								temporary.set(acmeAlias, serverKeyPair.getPrivate(), certificate.getCertificateChain().toArray(new X509Certificate[0]), null);
								ByteArrayOutputStream output = new ByteArrayOutputStream();
								temporary.save(output, artifact.getId());
								// set the key store in the clustered map so nodes can retrieve it on startup (or success handling)
								pkcs12 = output.toByteArray();
								map.put("pkcs12", pkcs12);
								
								// put it in the main keystore as well
								keystore.getKeyStore().set(acmeAlias, serverKeyPair.getPrivate(), certificate.getCertificateChain().toArray(new X509Certificate[0]), null);
								
								// we will emit a topic message in the finally that contains the pkcs12 which will be broadcast to all nodes and it will update the keystore
								
								// if we are persisting, save a copy of the received key store for analysis/testing
								if (persist) {
									File file = new File("acme-" + artifact.getId() + ".pkcs12");
									OutputStream fileOutput = new BufferedOutputStream(new FileOutputStream(file));
									try {
										fileOutput.write(pkcs12);
									}
									finally {
										fileOutput.close();
									}
								}
							}
							finally {
								artifact.releaseAllSubscriptions(pkcs12);
							}
						}
					}
					finally {
						lock.unlock();
					}
				}
				// make sure it uses the ACME alias
				virtualHost.getConfig().setKeyAlias(acmeAlias);
			}
			// if no one did (or it is nearly expired), get a lock
			// if you can't get a lock, wait for it, that means someone else is getting a new one
			// once you have the lock, check the shared map again, if still nothing, request it yourself and put it in the map
			// extensive logging
			// use a topic to subscribe for the http challenge setup & destruction
		}
		catch (RuntimeException e) {
			throw e;
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
		VerificationResult result = new VerificationResult();
		result.setCertificate(validCertificate);
		return result;
	}
}
