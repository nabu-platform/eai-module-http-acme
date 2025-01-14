/*
* Copyright (C) 2018 Alexander Verbruggen
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package be.nabu.eai.module.http.acme;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.net.URI;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.nabu.eai.module.http.server.HTTPServerArtifact;
import be.nabu.eai.module.http.virtual.VirtualHostArtifact;
import be.nabu.eai.module.keystore.KeyStoreArtifact;
import be.nabu.eai.repository.api.ClusteredServer;
import be.nabu.eai.repository.api.Repository;
import be.nabu.eai.repository.artifacts.jaxb.JAXBArtifact;
import be.nabu.libs.artifacts.api.StartableArtifact;
import be.nabu.libs.artifacts.api.StoppableArtifact;
import be.nabu.libs.cluster.api.ClusterInstance;
import be.nabu.libs.cluster.api.ClusterMessageListener;
import be.nabu.libs.cluster.api.ClusterSubscription;
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
import be.nabu.libs.resources.api.WritableResource;
import be.nabu.libs.resources.memory.MemoryDirectory;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.mime.impl.MimeHeader;
import be.nabu.utils.mime.impl.PlainMimeContentPart;
import be.nabu.utils.security.KeyStoreHandler;
import be.nabu.utils.security.StoreType;

public class AcmeArtifact extends JAXBArtifact<AcmeConfiguration> implements StartableArtifact, StoppableArtifact {

	private Logger logger = LoggerFactory.getLogger(getClass());
	private boolean started;
	private List<EventSubscription<HTTPRequest, HTTPResponse>> challengeHandlers = new ArrayList<EventSubscription<HTTPRequest, HTTPResponse>>();
	private Map<String, VirtualHostArtifact> customHosts = new HashMap<String, VirtualHostArtifact>();
	private HTTPServerArtifact customServer;
	private ClusterSubscription subscription;
	
	public static class HTTPChallenge implements Serializable {
		private String virtualHostId;
		private static final long serialVersionUID = 1L;
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
		public static HTTPChallenge completed(String virtualHostId, byte [] keystore) {
			HTTPChallenge challenge = new HTTPChallenge();
			challenge.setCompleted(true);
			challenge.setKeystore(keystore);
			challenge.setVirtualHostId(virtualHostId);
			return challenge;
		}
		public static HTTPChallenge challenge(String virtualHostId, String token, String authorization) {
			HTTPChallenge challenge = new HTTPChallenge();
			challenge.setToken(token);
			challenge.setAuthorization(authorization);
			challenge.setVirtualHostId(virtualHostId);
			return challenge;
		}
		public byte[] getKeystore() {
			return keystore;
		}
		public void setKeystore(byte[] keystore) {
			this.keystore = keystore;
		}
		public String getVirtualHostId() {
			return virtualHostId;
		}
		public void setVirtualHostId(String virtualHostId) {
			this.virtualHostId = virtualHostId;
		}
	}
	
	public AcmeArtifact(String id, ResourceContainer<?> directory, Repository repository) {
		super(id, directory, repository, "acme.xml", AcmeConfiguration.class);
	}

	public void releaseAllSubscriptions(String virtualHostId, byte [] keystore) {
		if (getRepository().getServiceRunner() instanceof ClusteredServer) {
			ClusterInstance cluster = ((ClusteredServer) getRepository().getServiceRunner()).getCluster();
			ClusterTopic<HTTPChallenge> topic = cluster.topic(getId() + ":http-challenge");
			topic.publish(HTTPChallenge.completed(virtualHostId, keystore));
		}
	}
	
	public void subscribe(String virtualHostId, String token, String authorization) {
		if (getRepository().getServiceRunner() instanceof ClusteredServer) {
			ClusterInstance cluster = ((ClusteredServer) getRepository().getServiceRunner()).getCluster();
			ClusterTopic<HTTPChallenge> topic = cluster.topic(getId() + ":http-challenge");
			topic.publish(HTTPChallenge.challenge(virtualHostId, token, authorization));
		}
	}
	
	private void subscribeForHTTPChallenge() {
		if (getRepository().getServiceRunner() instanceof ClusteredServer) {
			ClusterInstance cluster = ((ClusteredServer) getRepository().getServiceRunner()).getCluster();
			ClusterTopic<HTTPChallenge> topic = cluster.topic(getId() + ":http-challenge");
			logger.info("Subscribing to cluster topic: " + getId() + ":http-challenge");
			subscription = topic.subscribe(new ClusterMessageListener<AcmeArtifact.HTTPChallenge>() {
				@Override
				public void onMessage(final HTTPChallenge message) {
					try {
						VirtualHostArtifact virtualHost = (VirtualHostArtifact) getRepository().resolve(message.getVirtualHostId());
						// if it is completed, unregister all handlers
						if (message.isCompleted()) {
							logger.info("[{}] HTTP challenge completed", message.getVirtualHostId());
							VirtualHostArtifact customHost = customHosts.get(message.getVirtualHostId());
							if (customHost != null) {
								logger.info("[{}] Stopping custom virtual host", message.getVirtualHostId());
								try {
									customHost.stop();
								}
								catch (IOException e) {
									logger.error("[" + message.getVirtualHostId() + "] Could not stop custom virtual host", e);
								}
								customHosts.remove(message.getVirtualHostId());
							}
							if (customServer != null) {
								logger.info("[{}] Stopping custom http server", message.getVirtualHostId());
								try {
									customServer.stop();
								}
								catch (IOException e) {
									logger.error("[" + message.getVirtualHostId() + "] Could not stop custom http server", e);
								}
								customServer = null;
							}
							if (message.getKeystore() != null) {
								logger.info("[{}] Received new keystore", message.getVirtualHostId());
								
								KeyStoreArtifact keystore = virtualHost.getServer().getConfig().getKeystore();
								//String keyAlias = getConfig().getVirtualHost().getConfig().getKeyAlias();
								String acmeAlias = "acme2-" + message.getVirtualHostId();
								try {
									KeyStoreHandler toMerge = KeyStoreHandler.load(new ByteArrayInputStream(message.getKeystore()), getId(), StoreType.PKCS12);
									
									// set it in the server keystore so it can be used
									keystore.getKeyStore().set(acmeAlias, toMerge.getPrivateKey(acmeAlias, null), toMerge.getPrivateKeys().get(acmeAlias), null);
									
									// save the newly obtained certificate if the files are writable
									// this is especially interesting for non-clustered servers because without clustered map storage they would have to re-request it every boot
									// given the weekly limits, this could be problematic when the project is still being deployed often
									if (keystore.getDirectory().getChild("keystore.xml") instanceof WritableResource) {
										logger.info("[{}] Persisting keystore", getId());
										keystore.save(keystore.getDirectory());
									}
									
									logger.info("[{}] Updating security context", getId());
									// update the security context for the server so it picks up the new key
									virtualHost.getServer().updateSecurityContext();
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
							VirtualHostArtifact unsecure = customHosts.get(message.getVirtualHostId());
							if (unsecure == null) {
								for (VirtualHostArtifact host : getRepository().getArtifacts(VirtualHostArtifact.class)) {
									// we are looking for a virtual host with the same host name but not the one the acme artifact is mounted on (that is the secure one)
									if (!host.equals(virtualHost) && virtualHost.getConfig().getHost().equals(host.getConfig().getHost())) {
										// it must have a server and must not be configured for security 
										if (host.getServer() != null && host.getConfig().getKeyAlias() == null) {
											Integer port = host.getServer().getConfig().getPort();
											// and the port _must_ be 80 as it is a standardized protocol on this port
											if (port == null || port == 80) {
												unsecure = host;
												break;
											}
										}
									}
								}
							}
							// find a server on port 80 and add a dynamic host
							if (unsecure == null) {
								logger.info("[{}] Could not find unsecure host equivalent, checking for available servers", getId());
								HTTPServerArtifact server = customServer;
								if (server == null) {
									for (HTTPServerArtifact possible : getRepository().getArtifacts(HTTPServerArtifact.class)) {
										// can have disabled servers from other projects
										if (possible.getConfig().getKeystore() == null && (possible.getConfig().getPort() == null || possible.getConfig().getPort() == 80) && possible.getConfig().isEnabled()) {
											server = possible;
											break;
										}
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
										customServer.finish();
										server = customServer;
									}
									catch (IOException e) {
										logger.error("[" + getId() + "] Could not start custom http server", e);
									}
								}
								else {
									logger.info("[{}] Found existing unsecure http server: " + server.getId(), getId());
								}
								if (server != null) {
									logger.info("[{}] Starting custom unsecure virtual host", getId());
									VirtualHostArtifact customHost = new VirtualHostArtifact(getId() + ".host", new MemoryDirectory(), getRepository());
									customHost.getConfig().setServer(server);
									customHost.getConfig().setHost(virtualHost.getConfig().getHost());
									customHost.getConfig().setAliases(virtualHost.getConfig().getAliases());
									customHost.getConfig().setRedirectAliases(virtualHost.getConfig().getRedirectAliases());
									customHosts.put(message.getVirtualHostId(), customHost);
									try {
										customHost.start();
										unsecure = customHost;
									}
									catch (IOException e) {
										logger.error("[" + getId() + "] Could not start custom virtual host", e);
									}
								}
							}
							else {
								logger.info("[{}] Found existing unsecure host: " + unsecure.getId(), getId());
							}
							if (unsecure == null) {
								logger.error("[{}] Could not find unsecure host for: " + virtualHost.getConfig().getHost(), getId());
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
												logger.info("[{}] Incoming call: " + uri, getId());
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
					catch (Throwable e) {
						logger.error("[" + getId() + "] ACME throwable", e);
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

	@Override
	public void stop() throws IOException {
		started = false;
		if (subscription != null) {
			subscription.unsubscribe();
			subscription = null;
		}
	}
}
