"""Test security on the API level."""

from velodrome.lock8.utils import reverse_query


def test_superuser_cannot_see_affiliations(drf_root_admin, drf_renter):
    aff_uuid = drf_renter.user.affiliations.first().uuid

    url = reverse_query('lock8:affiliation-detail', kwargs={'uuid': aff_uuid})
    drf_root_admin.assert_404(url)
    drf_renter.assert_success(url)
