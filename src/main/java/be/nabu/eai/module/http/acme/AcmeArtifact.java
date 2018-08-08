package be.nabu.eai.module.http.acme;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.nabu.eai.module.http.server.HTTPServerArtifact;
import be.nabu.eai.module.http.virtual.VirtualHostArtifact;
import be.nabu.eai.module.keystore.KeyStoreArtifact;
import be.nabu.eai.repository.api.ClusteredServer;
import be.nabu.eai.repository.api.Repository;
import be.nabu.eai.repository.artifacts.jaxb.JAXBArtifact;
import be.nabu.libs.artifacts.api.StartableArtifact;
import be.nabu.libs.cluster.api.ClusterInstance;
import be.nabu.libs.cluster.api.ClusterMessageListener;
import be.nabu.libs.cluster.api.ClusterTopic;
import be.nabu.libs.events.api.EventHandler;
import be.nabu.libs.events.api.EventSubscription;
import be.nabu.libs.http.HTTPCodes;
import be.nabu.libs.http.HTTPException;
import be.nabu.libs.http.api.HTTPRequest;
import be.nabu.libs.http.api.HTTPResponse;
import be.nabu.libs.http.core.DefaultHTTPResponse;
import be.nabu.libs.http.core.HTTPUtils;
import be.nabu.libs.resources.api.ResourceContainer;
import be.nabu.libs.resources.memory.MemoryDirectory;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.mime.impl.MimeHeader;
import be.nabu.utils.mime.impl.PlainMimeContentPart;
import be.nabu.utils.security.KeyStoreHandler;
import be.nabu.utils.security.StoreType;

public class AcmeArtifact extends JAXBArtifact<AcmeConfiguration> implements StartableArtifact {

	private Logger logger = LoggerFactory.getLogger(getClass());
	private boolean started;
	private List<EventSubscription<HTTPRequest, HTTPResponse>> challengeHandlers = new ArrayList<EventSubscription<HTTPRequest, HTTPResponse>>();
	private VirtualHostArtifact customHost;
	private HTTPServerArtifact customServer;
	
	public static class HTTPChallenge {
		private boolean completed;
		private String authorization, token;
		private byte [] keystore;
		public boolean isCompleted() {
			return completed;
		}
		public void setCompleted(boolean completed) {
			this.completed = completed;
		}
		public String getAuthorization() {
			return authorization;
		}
		public void setAuthorization(String authorization) {
			this.authorization = authorization;
		}
		public String getToken() {
			return token;
		}
		public void setToken(String token) {
			this.token = token;
		}
		public static HTTPChallenge completed(byte [] keystore) {
			HTTPChallenge challenge = new HTTPChallenge();
			challenge.setCompleted(true);
			challenge.setKeystore(keystore);
			return challenge;
		}
		public static HTTPChallenge challenge(String token, String authorization) {
			HTTPChallenge challenge = new HTTPChallenge();
			challenge.setToken(token);
			challenge.setAuthorization(authorization);
			return challenge;
		}
		public byte[] getKeystore() {
			return keystore;
		}
		public void setKeystore(byte[] keystore) {
			this.keystore = keystore;
		}
	}
	
	public AcmeArtifact(String id, ResourceContainer<?> directory, Repository repository) {
		super(id, directory, repository, "acme.xml", AcmeConfiguration.class);
	}

	public void releaseAllSubscriptions(byte [] keystore) {
		if (getRepository().getServiceRunner() instanceof ClusteredServer) {
			ClusterInstance cluster = ((ClusteredServer) getRepository().getServiceRunner()).getCluster();
			ClusterTopic<HTTPChallenge> topic = cluster.topic(getId() + ":http-challenge");
			topic.publish(HTTPChallenge.completed(keystore));
		}
	}
	
	public void subscribe(String token, String authorization) {
		if (getRepository().getServiceRunner() instanceof ClusteredServer) {
			ClusterInstance cluster = ((ClusteredServer) getRepository().getServiceRunner()).getCluster();
			ClusterTopic<HTTPChallenge> topic = cluster.topic(getId() + ":http-challenge");
			topic.publish(HTTPChallenge.challenge(token, authorization));
		}
	}
	
	private void subscribeForHTTPChallenge() {
		if (getRepository().getServiceRunner() instanceof ClusteredServer) {
			ClusterInstance cluster = ((ClusteredServer) getRepository().getServiceRunner()).getCluster();
			ClusterTopic<HTTPChallenge> topic = cluster.topic(getId() + ":http-challenge");
			logger.info("Subscribing to cluster topic: " + getId() + ":http-challenge");
			topic.subscribe(new ClusterMessageListener<AcmeArtifact.HTTPChallenge>() {
				@Override
				public void onMessage(final HTTPChallenge message) {
					// if it is completed, unregister all handlers
					if (message.isCompleted()) {
						logger.info("[{}] HTTP challenge completed", getId());
						if (customHost != null) {
							logger.info("[{}] Stopping custom virtual host", getId());
							try {
								customHost.stop();
							}
							catch (IOException e) {
								logger.error("[" + getId() + "] Could not stop custom virtual host", e);
							}
							customHost = null;
						}
						if (customServer != null) {
							logger.info("[{}] Stopping custom http server", getId());
							try {
								customServer.stop();
							}
							catch (IOException e) {
								logger.error("[" + getId() + "] Could not stop custom http server", e);
							}
							customServer = null;
						}
						if (message.getKeystore() != null) {
							logger.info("[{}] Received new keystore", getId());
							
							KeyStoreArtifact keystore = getConfig().getVirtualHost().getConfig().getServer().getConfig().getKeystore();
							String keyAlias = getConfig().getVirtualHost().getConfig().getKeyAlias();
							String acmeAlias = "acme2-" + keyAlias;
							try {
								KeyStoreHandler toMerge = KeyStoreHandler.load(new ByteArrayInputStream(message.getKeystore()), getId(), StoreType.PKCS12);
								
								// set it in the server keystore so it can be used
								keystore.getKeyStore().set(acmeAlias, toMerge.getPrivateKey(acmeAlias, null), toMerge.getPrivateKeys().get(acmeAlias), null);
								
								// update the security context for the server so it picks up the new key
								getConfig().getVirtualHost().getConfig().getServer().updateSecurityContext();
							}
							catch (Exception e) {
								logger.error("[" + getId() + "] Could not set updated keystore", e);
							}
						}
						logger.info("[{}] Removing " + challengeHandlers.size() + " subscription(s)", getId());
						for (EventSubscription<HTTPRequest, HTTPResponse> challengeHandler : challengeHandlers) {
							challengeHandler.unsubscribe();
						}
						challengeHandlers.clear();
					}
					else {
						logger.info("[{}] Setting up HTTP challenge", getId());
						VirtualHostArtifact unsecure = null;
						for (VirtualHostArtifact host : getRepository().getArtifacts(VirtualHostArtifact.class)) {
							// we are looking for a virtual host with the same host name
							if (!host.equals(this) && getConfig().getVirtualHost().getConfig().getHost().equals(host.getConfig().getHost())) {
								// it must have a server and must not be configured for security 
								if (host.getConfig().getServer() != null && host.getConfig().getKeyAlias() == null) {
									Integer port = host.getConfig().getServer().getConfig().getPort();
									// and the port _must_ be 80 as it is a standardized protocol on this port
									if (port == null || port == 80) {
										unsecure = host;
										break;
									}
								}
							}
						}
						// find a server on port 80 and add a dynamic host
						if (unsecure == null) {
							logger.info("[{}] Could not find unsecure host equivalent, checking for available servers", getId());
							HTTPServerArtifact server = null;
							for (HTTPServerArtifact possible : getRepository().getArtifacts(HTTPServerArtifact.class)) {
								if (possible.getConfig().getKeystore() == null && (possible.getConfig().getPort() == null || possible.getConfig().getPort() == 80)) {
									server = possible;
									break;
								}
							}
							// if we have no server, start one up on 80
							if (server == null) {
								logger.info("[{}] Starting custom unsecure http server", getId());
								customServer = new HTTPServerArtifact(getId() + ".server", new MemoryDirectory(), getRepository());
								customServer.getConfig().setEnabled(true);
								customServer.getConfig().setPort(80);
								try {
									customServer.start();
									server = customServer;
								}
								catch (IOException e) {
									logger.error("[" + getId() + "] Could not start custom http server", e);
								}
							}
							if (server != null) {
								logger.info("[{}] Starting custom unsecure virtual host", getId());
								customHost = new VirtualHostArtifact(getId() + ".host", new MemoryDirectory(), getRepository());
								customHost.getConfig().setServer(server);
								customHost.getConfig().setHost(getConfig().getVirtualHost().getConfig().getHost());
								customHost.getConfig().setAliases(getConfig().getVirtualHost().getConfig().getAliases());
								try {
									customHost.start();
									unsecure = customHost;
								}
								catch (IOException e) {
									logger.error("[" + getId() + "] Could not start custom virtual host", e);
								}
							}
						}
						if (unsecure == null) {
							logger.error("[{}] Could not find unsecure host for: " + getConfig().getVirtualHost().getConfig().getHost(), getId());
						}
						else {
							final String path = "/.well-known/acme-challenge/" + message.getToken();
							logger.info("[{}] Listening for call to: " + path, getId());
							EventSubscription<HTTPRequest, HTTPResponse> challengeHandler = unsecure.getDispatcher().subscribe(HTTPRequest.class, new EventHandler<HTTPRequest, HTTPResponse>() {
								@Override
								public HTTPResponse handle(HTTPRequest request) {
									try {
										URI uri = HTTPUtils.getURI(request, false);
										if (uri.getPath().equals(path)) {
											byte [] content = message.getAuthorization().getBytes(Charset.forName("UTF-8"));
											return new DefaultHTTPResponse(200, HTTPCodes.getMessage(200), new PlainMimeContentPart(null, 
												IOUtils.wrap(content, true), 
												new MimeHeader("Content-Length", "" + content.length)));
										}
									}
									catch (Exception e) {
										throw new HTTPException(500, e);
									}
									return null;
								}
							});
							// make sure it is at the front of the handlers
							challengeHandler.promote();
							challengeHandlers.add(challengeHandler);
						}
					}
				}
			});
		}
	}

	@Override
	public void start() throws IOException {
		subscribeForHTTPChallenge();
		started = true;
	}

	@Override
	public boolean isStarted() {
		return started;
	}
}
