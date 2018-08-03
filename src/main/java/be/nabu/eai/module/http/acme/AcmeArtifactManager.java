package be.nabu.eai.module.http.acme;

import be.nabu.eai.repository.api.Repository;
import be.nabu.eai.repository.managers.base.JAXBArtifactManager;
import be.nabu.libs.resources.api.ResourceContainer;

public class AcmeArtifactManager extends JAXBArtifactManager<AcmeConfiguration, AcmeArtifact> {

	public AcmeArtifactManager() {
		super(AcmeArtifact.class);
	}

	@Override
	protected AcmeArtifact newInstance(String id, ResourceContainer<?> container, Repository repository) {
		return new AcmeArtifact(id, container, repository);
	}
}
