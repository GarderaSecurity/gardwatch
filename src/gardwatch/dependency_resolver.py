"""Dependency chain resolver for supply-chain scanning."""
import logging
from typing import List
from .models import Dependency, DependencyTree, DependencyNode
from .clients.depsdev import DepsDevClient

logger = logging.getLogger(__name__)


class DependencyResolver:
    """Resolves and analyzes dependency chains for supply-chain attacks."""

    def __init__(self, deps_client: DepsDevClient):
        """
        Initialize resolver.

        Args:
            deps_client: Client for fetching package metadata
        """
        self.deps_client = deps_client
        self.dependency_tree: DependencyTree = None

    async def resolve_dependency_chain(
        self,
        root_dependency: Dependency
    ) -> DependencyTree:
        """
        Fetch the full dependency tree for a package using deps.dev.

        Args:
            root_dependency: The package to start from

        Returns:
            DependencyTree model with all dependencies
        """
        logger.info(f"Resolving dependency chain for {root_dependency.name}")

        self.dependency_tree = await self.deps_client.get_dependency_tree(root_dependency)

        if not self.dependency_tree:
            logger.warning(f"No dependency tree found for {root_dependency.name}")
            # Return empty tree
            from .models import DependencyTree
            self.dependency_tree = DependencyTree(nodes=[])
            return self.dependency_tree

        all_deps = self.dependency_tree.get_all_dependencies()
        direct_deps = self.dependency_tree.get_direct_dependencies()
        transitive_deps = self.dependency_tree.get_transitive_dependencies()

        logger.info(
            f"Found {len(all_deps)} total dependencies: "
            f"{len(direct_deps)} direct, {len(transitive_deps)} transitive"
        )

        return self.dependency_tree

    def get_dependency_tree_summary(self) -> str:
        """Generate a human-readable summary of the dependency tree."""
        if not self.dependency_tree or not self.dependency_tree.nodes:
            return "No dependencies found"

        all_deps = self.dependency_tree.get_all_dependencies()
        direct_deps = self.dependency_tree.get_direct_dependencies()
        transitive_deps = self.dependency_tree.get_transitive_dependencies()

        lines = [
            f"Total dependencies: {len(all_deps)}",
            f"  Direct dependencies: {len(direct_deps)}",
            f"  Transitive dependencies: {len(transitive_deps)}"
        ]

        return "\n".join(lines)

    def get_all_unique_dependencies(self) -> List[Dependency]:
        """
        Get a flat list of all unique dependencies for scanning.

        Returns:
            List of unique Dependency objects
        """
        if not self.dependency_tree:
            return []

        # Convert DependencyNode objects to Dependency objects
        dependencies = []
        for node in self.dependency_tree.get_all_dependencies():
            dep = Dependency(
                name=node.versionKey.name,
                version=node.versionKey.version,
                ecosystem=node.versionKey.system.lower()
            )
            dependencies.append(dep)

        return dependencies
