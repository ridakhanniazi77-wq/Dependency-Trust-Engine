
from app import Package, Manifest, calculate_risk, create_graph
from pydantic import ValidationError
import pytest


def test_routine_review():
    package = Package(
        name="test-package",
        version="1.0",
        advisory_points=5,
        maintenance_points=5
    )
    score, level = calculate_risk(package)
    assert score == 10
    assert level == "Routine review"


def test_review_priority():
    package = Package(
        name="test-package",
        version="1.0",
        advisory_points=20,
        maintenance_points=10
    )
    score, level = calculate_risk(package)
    assert score == 30
    assert level == "Review"


def test_high_priority():
    package = Package(
        name="test-package",
        version="1.0",
        advisory_points=35,
        maintenance_points=15
    )
    score, level = calculate_risk(package)
    assert score == 50
    assert level == "High priority"


def test_urgent_review():
    package = Package(
        name="test-package",
        version="1.0",
        advisory_points=35,
        maintenance_points=20,
        provenance_points=20
    )
    score, level = calculate_risk(package)
    assert score == 75
    assert level == "Urgent review"


def test_invalid_advisory_points():
    with pytest.raises(ValidationError):
        Package(
            name="test-package",
            version="1.0",
            advisory_points=40
        )


def test_dependency_graph():
    packages = [
        Package(
            name="flask",
            version="3.0.0",
            dependencies=["requests"]
        ),
        Package(
            name="requests",
            version="2.31.0",
            dependencies=[]
        )
    ]

    graph = create_graph(packages)

    assert graph.has_node("flask")
    assert graph.has_node("requests")
    assert graph.has_edge("flask", "requests")


def test_empty_manifest():
    with pytest.raises(ValidationError):
        Manifest(
            project_name="Empty Project",
            packages=[]
        )
