package be.nabu.eai.module.http.acme;

import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import be.nabu.eai.api.EnvironmentSpecific;
import be.nabu.eai.module.http.virtual.VirtualHostArtifact;
import be.nabu.eai.repository.jaxb.ArtifactXMLAdapter;

public class AcmeConfiguration {
	private boolean enabled;
	private VirtualHostArtifact virtualHost;

	// you need to be able to turn it off in dev (and possibly qlty) and enable it only in environments that are public
	@EnvironmentSpecific
	public boolean isEnabled() {
		return enabled;
	}
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
	
	@XmlJavaTypeAdapter(value = ArtifactXMLAdapter.class)
	public VirtualHostArtifact getVirtualHost() {
		return virtualHost;
	}
	public void setVirtualHost(VirtualHostArtifact virtualHost) {
		this.virtualHost = virtualHost;
	}
	
}
