import rules

from velodrome.lock8.predicates import (
    is_admin_of_lock8, is_at_least_fleet_op_of_descendant_organization,
    is_at_least_fleet_op_or_admin_of_lock8,
    is_at_least_mechanic_or_admin_of_lock8, is_superuser,
)

admin_user_or_fleet_op = (
    is_superuser |
    (
        is_at_least_fleet_op_of_descendant_organization &
        is_at_least_fleet_op_or_admin_of_lock8
    ) |
    is_admin_of_lock8
)

# TagGroup
tag_group_perm = is_superuser | is_admin_of_lock8
rules.add_perm(
    'custom_tagging.view_taggroup',
    is_at_least_mechanic_or_admin_of_lock8
)
rules.add_perm('custom_tagging.add_taggroup', tag_group_perm)
rules.add_perm('custom_tagging.change_taggroup', tag_group_perm)
rules.add_perm('custom_tagging.delete_taggroup', tag_group_perm)

# TagDeclaration
rules.add_perm(
    'custom_tagging.view_tagdeclaration',
    is_at_least_mechanic_or_admin_of_lock8
)
rules.add_perm('custom_tagging.add_tagdeclaration', admin_user_or_fleet_op)
rules.add_perm('custom_tagging.change_tagdeclaration', admin_user_or_fleet_op)
rules.add_perm('custom_tagging.delete_tagdeclaration', admin_user_or_fleet_op)

# TagInstance
tag_instance_perm = is_at_least_mechanic_or_admin_of_lock8
rules.add_perm('custom_tagging.view_taginstance', tag_instance_perm)
rules.add_perm('custom_tagging.add_taginstance', tag_instance_perm)
rules.add_perm('custom_tagging.change_taginstance', tag_instance_perm)
rules.add_perm('custom_tagging.delete_taginstance', tag_instance_perm)
