# Service Lifecycle

## Creating a service

1. Create a feature branch from the latest `main`.
2. Generate the service:

   ```bash
   ./scripts/create-service.sh \
     example-service \
     "Flashcards Example Service" \
     --owner backend-team

    ```

3. Document the service responsibilities in its README.md.
4. Review OWNERS.yaml and TEMPLATE_METADATA.yaml.
5. Add the service to compose.yaml.
6. Add or update API and event schemas under contracts/.
7. Run the service quality gate and repository checks.
8. Open a pull request linked to the Jira issue.
The generated service must remain independently installable, testable, and buildable.

## Upgrading a service
1. Update the shared template in templates/fastapi-microservice.
2. Increment the generator version when the generated structure changes.
3. Verify template conformance by generating a temporary service.
4. Apply required changes to existing services in explicit pull requests.
5. Do not overwrite service-specific business logic or configuration.

## Removing a service
1. Confirm that no active consumer depends on the service.
2. Define a data retention or migration plan.
3. Remove the service from compose.yaml.
4. Remove its Helm and Terraform configuration.
5. Remove or deprecate its API and event contracts.
6. Remove the service directory.
7. Update repository documentation.
8. Verify repository checks before merging.

## Ownership
Every service must contain an OWNERS.yaml file. The declared owner is responsible for its code, contracts, operational documentation, and deployment configuration.