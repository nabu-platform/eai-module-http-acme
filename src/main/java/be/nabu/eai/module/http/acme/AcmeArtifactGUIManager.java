package be.nabu.eai.module.http.acme;

import java.io.IOException;
import java.util.List;

import be.nabu.eai.developer.MainController;
import be.nabu.eai.developer.managers.base.BaseJAXBGUIManager;
import be.nabu.eai.repository.resources.RepositoryEntry;
import be.nabu.libs.property.api.Property;
import be.nabu.libs.property.api.Value;

public class AcmeArtifactGUIManager extends BaseJAXBGUIManager<AcmeConfiguration, AcmeArtifact> {

	public AcmeArtifactGUIManager() {
		super("Acme", AcmeArtifact.class, new AcmeArtifactManager(), AcmeConfiguration.class);
	}

	@Override
	protected List<Property<?>> getCreateProperties() {
		return null;
	}

	@Override
	protected AcmeArtifact newInstance(MainController controller, RepositoryEntry entry, Value<?>... values) throws IOException {
		return new AcmeArtifact(entry.getId(), entry.getContainer(), entry.getRepository());
	}

	@Override
	public String getCategory() {
		return "Security";
	}
}
