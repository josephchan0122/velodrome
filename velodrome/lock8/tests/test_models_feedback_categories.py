import pytest


def test_feedback_category_model(alice, bicycle, owner, org, root_org):
    from velodrome.lock8.models import Feedback, FeedbackCategory

    assert org.feedback_category_tree is None
    org_category_tree = org.get_feedback_category_tree()
    assert org_category_tree == root_org.feedback_category_tree

    bicycle_category = org_category_tree.get_descendants().get(name='bicycle')
    c1 = FeedbackCategory.objects.create(name='wheel', parent=bicycle_category)
    c2 = FeedbackCategory.objects.create(
        name='flat-tyre', parent=c1,
        severity=FeedbackCategory.SEVERITY_HIGH
    )

    feedback = Feedback.objects.create(
        owner=owner,
        organization=org,
        user=alice,
        causality=bicycle,
        category=c2
    )

    assert not feedback.image
    assert not feedback.message

    assert feedback.category == c2
    assert feedback.category.name == 'flat-tyre'
    assert feedback.category.severity == FeedbackCategory.SEVERITY_HIGH
    assert feedback.category.is_leaf_node()

    assert not feedback.category.is_descendant_of(
        root_org.feedback_category_tree
        .get_descendants()
        .get(name='lock')
    )


def test_feedback_category_severity_ordering():
    from velodrome.lock8.models import FeedbackCategory as f, Severity as S
    assert S(f.SEVERITY_LOW) < S(f.SEVERITY_MEDIUM) < S(f.SEVERITY_HIGH)
    assert S(f.SEVERITY_HIGH) > S(f.SEVERITY_MEDIUM) > S(f.SEVERITY_LOW)
    with pytest.raises(TypeError):
        S(666)
    with pytest.raises(NotImplementedError):
        S('not') < S('implemented')
