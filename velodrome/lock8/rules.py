import rules

from .predicates import (
    can_access_analytics_feature, has_task_viewable_role, is_admin_of_lock8,
    is_allowed_by_email_domain, is_anon_and_invitation_provisioned,
    is_assigned_to_group, is_at_least_fleet_op_of_descendant_organization,
    is_at_least_fleet_op_of_descendant_organization_but_self,
    is_at_least_fleet_op_or_admin_of_lock8,
    is_at_least_mechanic_of_descendant_organization,
    is_at_least_mechanic_or_admin_of_lock8, is_at_least_renter,
    is_at_least_supervisor_of_descendant_organization,
    is_at_least_supervisor_or_admin_of_lock8, is_by_bicycle_state,
    is_category_viewable, is_closed_fleet, is_current_renter,
    is_current_renter_or_reserver, is_eligible_for_plan, is_local, is_mechanic,
    is_member_of_closed_fleet, is_open_fleet, is_owned_by,
    is_production_software, is_rentable, is_renting_the_attached_bicycle,
    is_reservable, is_self, is_superuser, is_used_by,
)

# Module
rules.add_perm('lock8', rules.predicates.is_staff)

admin_user_or_fleet_op = (
    is_superuser |
    (
        is_at_least_fleet_op_of_descendant_organization &
        is_at_least_fleet_op_or_admin_of_lock8
    ) |
    is_admin_of_lock8
)

admin_user_or_at_least_supervisor = (
    is_superuser |
    (
        is_at_least_supervisor_of_descendant_organization &
        is_at_least_supervisor_or_admin_of_lock8
    ) |
    is_admin_of_lock8
)

# RelatedField
rules.add_perm('set_related_organization',
               admin_user_or_fleet_op | is_member_of_closed_fleet)

# Address
rules.add_perm('lock8.add_address',
               is_superuser |
               is_at_least_fleet_op_or_admin_of_lock8)
rules.add_perm('lock8.view_address', admin_user_or_fleet_op)
rules.add_perm('lock8.change_address', admin_user_or_fleet_op)
rules.add_perm('lock8.delete_address', admin_user_or_fleet_op)
rules.add_perm('lock8.view_address_transitions', admin_user_or_fleet_op)


# Affiliation
rules.add_perm('lock8.add_affiliation',
               is_superuser |
               is_at_least_fleet_op_or_admin_of_lock8)
rules.add_perm('lock8.view_affiliation', (is_used_by &
                                          rules.predicates.is_authenticated) |
               admin_user_or_fleet_op)
rules.add_perm('lock8.change_affiliation', admin_user_or_fleet_op)
rules.add_perm('lock8.delete_affiliation', admin_user_or_fleet_op)

# Alert
rules.add_perm('lock8.view_alert', admin_user_or_fleet_op)

rules.add_perm('lock8.add_alert', is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.change_alert', is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.delete_alert', is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.resolve_alert', admin_user_or_fleet_op)
rules.add_perm('lock8.escalate_alert', admin_user_or_fleet_op)
rules.add_perm('lock8.stop_alert', admin_user_or_fleet_op)
rules.add_perm('lock8.silence_alert', admin_user_or_fleet_op)
rules.add_perm('lock8.view_alert_transitions', admin_user_or_fleet_op)

# AlertMessage
rules.add_perm('lock8.view_alertmessage',
               is_superuser | is_used_by)
rules.add_perm('lock8.add_alertmessage', is_superuser)
rules.add_perm('lock8.change_alertmessage', is_superuser | is_used_by)
rules.add_perm('lock8.delete_alertmessage', is_superuser | is_used_by)
rules.add_perm('lock8.acknowledge_alertmessage',
               is_superuser | is_used_by)
rules.add_perm('lock8.send_alertmessage',
               is_superuser | is_used_by)
rules.add_perm('lock8.view_alertmessage_transitions', admin_user_or_fleet_op)

# AxaLock
rules.add_perm('lock8.view_axalock', admin_user_or_fleet_op)

rules.add_perm('lock8.add_axalock', is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.change_axalock', is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.delete_axalock', is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.claim_axalock', is_superuser | is_admin_of_lock8
               | (admin_user_or_fleet_op & is_owned_by))
rules.add_perm('lock8.declare_transferable_axalock',
               is_superuser | is_admin_of_lock8
               | (admin_user_or_fleet_op & is_owned_by))
rules.add_perm('lock8.declare_stored_axalock',
               is_superuser | is_admin_of_lock8
               | (admin_user_or_fleet_op & is_owned_by))
rules.add_perm('lock8.view_axalock_transitions',
               is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.view_axalock_otp', admin_user_or_fleet_op)
rules.add_perm('lock8.report_axa_lock_status_axalock', admin_user_or_fleet_op)

# Bicycle
rules.add_perm('lock8.add_bicycle',
               is_superuser |
               is_at_least_fleet_op_or_admin_of_lock8)
rules.add_perm('lock8.view_bicycle',
               is_superuser | is_by_bicycle_state)
rules.add_perm('lock8.change_bicycle', admin_user_or_fleet_op)
rules.add_perm('lock8.delete_bicycle', admin_user_or_fleet_op)
rules.add_perm('lock8.put_in_maintenance_bicycle', admin_user_or_fleet_op)
rules.add_perm('lock8.declare_available_bicycle', admin_user_or_fleet_op)
rules.add_perm('lock8.declare_lost_bicycle', admin_user_or_fleet_op)
rules.add_perm('lock8.declare_unrecoverable_bicycle', admin_user_or_fleet_op)
rules.add_perm('lock8.reserve_bicycle',
               is_superuser |
               (is_member_of_closed_fleet & is_at_least_renter) |
               (is_closed_fleet & (
                is_at_least_fleet_op_of_descendant_organization) |
                (rules.predicates.is_authenticated & is_open_fleet &
                    is_at_least_renter & is_reservable)))
rules.add_perm('lock8.rent_bicycle',
               is_superuser |
               (is_member_of_closed_fleet & is_at_least_renter) |
               (is_closed_fleet & (
                is_at_least_fleet_op_of_descendant_organization) |
                (rules.predicates.is_authenticated & is_open_fleet &
                    is_rentable)))
rules.add_perm('lock8.force_put_in_maintenance_bicycle',
               admin_user_or_fleet_op)
rules.add_perm('lock8.take_over_bicycle', admin_user_or_fleet_op)
rules.add_perm('lock8.cancel_reservation_bicycle',
               is_superuser | is_current_renter_or_reserver)
rules.add_perm('lock8.return_bicycle',
               is_superuser | is_current_renter_or_reserver)
rules.add_perm('lock8.retire_bicycle', admin_user_or_fleet_op)
rules.add_perm('lock8.view_bicycle_stats', admin_user_or_fleet_op)
rules.add_perm('lock8.view_bicycle_pricings',
               is_superuser |
               (is_member_of_closed_fleet & is_at_least_renter) |
               (is_closed_fleet & (
                is_at_least_fleet_op_of_descendant_organization) |
                (rules.predicates.is_authenticated & is_open_fleet &
                    is_rentable)))
rules.add_perm('lock8.view_bicycle_transitions', admin_user_or_fleet_op)
axa_perm = is_superuser | is_at_least_renter & is_current_renter_or_reserver
rules.add_perm('lock8.view_bicycle_otp', axa_perm)
rules.add_perm('lock8.report_axa_lock_status_bicycle', axa_perm)
view_shared_secret_perm = (
    is_superuser |
    (is_at_least_mechanic_of_descendant_organization &
     is_at_least_mechanic_or_admin_of_lock8) |
    (is_member_of_closed_fleet & is_at_least_renter & is_current_renter))
rules.add_perm('lock8.view_bicycle_shared_secret', view_shared_secret_perm)

# BicycleModel
rules.add_perm('lock8.add_bicyclemodel',
               is_superuser |
               is_at_least_fleet_op_or_admin_of_lock8)
rules.add_perm('lock8.view_bicyclemodel',
               is_superuser | is_open_fleet | is_member_of_closed_fleet)
rules.add_perm('lock8.change_bicyclemodel', admin_user_or_fleet_op)
rules.add_perm('lock8.delete_bicyclemodel', admin_user_or_fleet_op)
rules.add_perm('lock8.view_bicyclemodel_transitions', admin_user_or_fleet_op)

# BicycleType
rules.add_perm('lock8.add_bicycletype', is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.view_bicycletype', rules.predicates.is_authenticated)
rules.add_perm('lock8.change_bicycletype', is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.delete_bicycletype', is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.view_bicycletype_transitions', admin_user_or_fleet_op)

# BMMR
bmmr_perm = admin_user_or_fleet_op
rules.add_perm('lock8.add_bicyclemodelmaintenancerule', bmmr_perm)
rules.add_perm('lock8.view_bicyclemodelmaintenancerule', bmmr_perm)
rules.add_perm('lock8.change_bicyclemodelmaintenancerule', bmmr_perm)
rules.add_perm('lock8.delete_bicyclemodelmaintenancerule', bmmr_perm)
rules.add_perm('lock8.deactivate_bicyclemodelmaintenancerule', bmmr_perm)
rules.add_perm('lock8.activate_bicyclemodelmaintenancerule', bmmr_perm)

# Stripe
rules.add_perm('lock8.view_user_ephemeralkey', is_superuser | (
    is_self & rules.predicates.is_authenticated))
rules.add_perm('lock8.view_user_subscriptions', is_superuser | (
    is_self & rules.predicates.is_authenticated))

# ClientApp
rules.add_perm('lock8.add_clientapp', is_superuser |
               is_at_least_fleet_op_or_admin_of_lock8)
rules.add_perm('lock8.view_clientapp', is_superuser |
               is_at_least_fleet_op_or_admin_of_lock8)
rules.add_perm('lock8.change_clientapp', is_superuser |
               is_at_least_fleet_op_or_admin_of_lock8)
rules.add_perm('lock8.delete_clientapp', is_superuser |
               is_at_least_fleet_op_or_admin_of_lock8)

# Dashboard
rules.add_perm('lock8.view_dashboard',
               is_superuser | is_at_least_fleet_op_or_admin_of_lock8)

# Feature
rules.add_perm('lock8.add_feature', is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.view_feature', is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.change_feature', is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.delete_feature', is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.activate_feature', is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.deactivate_feature', is_superuser | is_admin_of_lock8)

# Metrics
rules.add_perm('lock8.view_metrics',
               is_superuser | is_admin_of_lock8 |
               rules.predicates.is_authenticated &
               can_access_analytics_feature)

# Invitation
rules.add_perm('lock8.add_invitation',
               is_superuser |
               is_at_least_fleet_op_or_admin_of_lock8)
rules.add_perm('lock8.view_invitation', admin_user_or_fleet_op |
               (rules.predicates.is_authenticated & is_at_least_renter) |
               is_anon_and_invitation_provisioned)
rules.add_perm('lock8.change_invitation', admin_user_or_fleet_op)
rules.add_perm('lock8.delete_invitation', admin_user_or_fleet_op)
rules.add_perm('lock8.provision_invitation', admin_user_or_fleet_op)
rules.add_perm('lock8.resend_invitation', admin_user_or_fleet_op)
rules.add_perm('lock8.cancel_invitation', admin_user_or_fleet_op)
rules.add_perm('lock8.confirm_invitation',
               is_superuser | rules.predicates.is_authenticated &
               is_at_least_renter)
rules.add_perm('lock8.decline_invitation',
               is_superuser | rules.predicates.is_authenticated &
               is_at_least_renter)
rules.add_perm('lock8.view_invitation_transitions', admin_user_or_fleet_op)

# Lock
rules.add_perm('lock8.view_lock', admin_user_or_fleet_op)

rules.add_perm('lock8.add_lock', is_superuser | is_admin_of_lock8 |
               is_production_software)
rules.add_perm('lock8.change_lock', is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.delete_lock', is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.provision_lock', admin_user_or_at_least_supervisor)
rules.add_perm('lock8.decommission_lock', is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.activate_lock', admin_user_or_at_least_supervisor)
rules.add_perm('lock8.put_in_maintenance_lock', admin_user_or_fleet_op)
rules.add_perm('lock8.restore_lock', admin_user_or_fleet_op)
rules.add_perm('lock8.import_lock_csv_file',
               is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.view_lock_transitions',
               is_superuser | is_admin_of_lock8)

# Firmware
rules.add_perm('lock8.view_firmware', is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.add_firmware', is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.change_firmware', is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.delete_firmware', is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.provision_firmware', is_superuser | is_admin_of_lock8)

# LockFirmwareUpdate
rules.add_perm('lock8.view_lockfirmwareupdate',
               is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.add_lockfirmwareupdate',
               is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.change_lockfirmwareupdate',
               is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.delete_lockfirmwareupdate',
               is_superuser | is_admin_of_lock8)

# SupportTicket
ticket_predicate = admin_user_or_fleet_op
rules.add_perm('lock8.view_supportticket', ticket_predicate |
               (is_owned_by & rules.predicates.is_authenticated))
rules.add_perm('lock8.add_supportticket', ticket_predicate |
               (is_owned_by & rules.predicates.is_authenticated &
                is_at_least_renter))
rules.add_perm('lock8.change_supportticket', ticket_predicate |
               (is_owned_by & rules.predicates.is_authenticated))
rules.add_perm('lock8.delete_supportticket', ticket_predicate)

# Feedback
feedback_predicate = admin_user_or_fleet_op
rules.add_perm('lock8.view_feedback', feedback_predicate |
               (is_used_by & rules.predicates.is_authenticated))
rules.add_perm('lock8.add_feedback', feedback_predicate |
               (is_used_by & rules.predicates.is_authenticated &
                is_at_least_renter))
rules.add_perm('lock8.change_feedback', feedback_predicate |
               (is_used_by & rules.predicates.is_authenticated))
rules.add_perm('lock8.escalate_feedback', feedback_predicate)
rules.add_perm('lock8.discard_feedback', feedback_predicate)
rules.add_perm('lock8.delete_feedback', feedback_predicate)
rules.add_perm('lock8.view_feedback_transitions', feedback_predicate)


# FeedbackCategory
rules.add_perm('lock8.add_feedbackcategory',
               is_superuser |
               is_at_least_fleet_op_or_admin_of_lock8)
rules.add_perm('lock8.view_feedbackcategory',
               is_superuser | (is_category_viewable &
                               rules.predicates.is_authenticated))
rules.add_perm('lock8.change_feedbackcategory', admin_user_or_fleet_op)
rules.add_perm('lock8.delete_feedbackcategory', admin_user_or_fleet_op)

# NotificationMessage
rules.add_perm('lock8.add_notificationmessage', is_superuser)
rules.add_perm('lock8.view_notificationmessage', is_superuser |
               (is_used_by & rules.predicates.is_authenticated))
rules.add_perm('lock8.change_notificationmessage', is_superuser |
               (is_used_by & rules.predicates.is_authenticated))
rules.add_perm('lock8.delete_notificationmessage', is_superuser |
               (is_used_by & rules.predicates.is_authenticated))
rules.add_perm('lock8.acknowledge_notificationmessage',
               is_superuser |
               (is_used_by & rules.predicates.is_authenticated))
rules.add_perm('lock8.send_notificationmessage', is_superuser |
               (is_used_by & rules.predicates.is_authenticated))

# Organization
view_org_perm = (is_superuser | is_open_fleet | is_member_of_closed_fleet |
                 is_allowed_by_email_domain)
rules.add_perm('lock8.view_organization', view_org_perm)
rules.add_perm('lock8.add_organization', is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.change_organization', admin_user_or_fleet_op)
rules.add_perm('lock8.delete_organization',
               is_superuser |
               is_at_least_fleet_op_of_descendant_organization_but_self)
rules.add_perm('lock8.view_organization_transitions', admin_user_or_fleet_op)
rules.add_perm('lock8.view_organization_preference', view_org_perm)
rules.add_perm('lock8.preference_organization', admin_user_or_fleet_op)

# OrganizationPreference
rules.add_perm('lock8.add_organizationpreference',
               is_superuser | is_at_least_fleet_op_or_admin_of_lock8)
rules.add_perm('lock8.view_organizationpreference', admin_user_or_fleet_op)
rules.add_perm('lock8.change_organizationpreference', admin_user_or_fleet_op)
rules.add_perm('lock8.delete_organizationpreference', admin_user_or_fleet_op)
rules.add_perm('lock8.view_organizationpreference_transitions',
               admin_user_or_fleet_op)

# Photo
rules.add_perm('lock8.view_photo',
               is_superuser | is_open_fleet | is_member_of_closed_fleet)
rules.add_perm('lock8.add_photo',
               is_superuser | is_at_least_fleet_op_or_admin_of_lock8)
rules.add_perm('lock8.change_photo', admin_user_or_fleet_op)
rules.add_perm('lock8.delete_photo', admin_user_or_fleet_op)
rules.add_perm('lock8.view_photo_transitions', admin_user_or_fleet_op)

# PricingScheme
rules.add_perm('lock8.view_pricingscheme',
               is_superuser | is_open_fleet | is_member_of_closed_fleet)
rules.add_perm('lock8.add_pricingscheme',
               is_superuser | is_at_least_fleet_op_or_admin_of_lock8)
rules.add_perm('lock8.change_pricingscheme', admin_user_or_fleet_op)
rules.add_perm('lock8.delete_pricingscheme', admin_user_or_fleet_op)
rules.add_perm('lock8.view_pricingscheme_transitions', admin_user_or_fleet_op)
rules.add_perm('lock8.view_pricingscheme_compute_amount',
               is_superuser | is_open_fleet | is_member_of_closed_fleet)

# RefreshToken
rules.add_perm('refreshtoken.add_refreshtoken',
               is_superuser | is_admin_of_lock8)
rules.add_perm('refreshtoken.view_refreshtoken',
               is_superuser | is_admin_of_lock8)
rules.add_perm('refreshtoken.change_refreshtoken',
               is_superuser | is_admin_of_lock8)
rules.add_perm('refreshtoken.delete_refreshtoken',
               is_superuser | is_admin_of_lock8)
rules.add_perm('refreshtoken.revoke_refreshtoken',
               is_superuser | is_admin_of_lock8 |
               rules.predicates.is_authenticated & is_used_by)

# RentalSession
rules.add_perm('lock8.view_rentalsession', (
        is_admin_of_lock8 |
        is_at_least_fleet_op_of_descendant_organization |
        (is_at_least_renter & is_owned_by)))
rules.add_perm('lock8.change_rentalsession', admin_user_or_fleet_op)
rules.add_perm('lock8.delete_rentalsession', admin_user_or_fleet_op)
rules.add_perm('lock8.view_rentalsession_transitions', (
        is_admin_of_lock8 |
        is_at_least_fleet_op_of_descendant_organization |
        (is_at_least_renter & is_owned_by)))

# RentingScheme
rules.add_perm('lock8.add_rentingscheme',
               is_superuser |
               is_at_least_fleet_op_or_admin_of_lock8)
rules.add_perm('lock8.view_rentingscheme',
               is_superuser | is_by_bicycle_state)
rules.add_perm('lock8.change_rentingscheme', admin_user_or_fleet_op)
rules.add_perm('lock8.delete_rentingscheme', admin_user_or_fleet_op)
rules.add_perm('lock8.view_rentingscheme_transitions', admin_user_or_fleet_op)

# Reservation
rules.add_perm('lock8.view_reservation', (
        is_admin_of_lock8 |
        is_at_least_fleet_op_of_descendant_organization |
        (is_at_least_renter & is_owned_by)))
rules.add_perm('lock8.change_reservation', admin_user_or_fleet_op)
rules.add_perm('lock8.delete_reservation', admin_user_or_fleet_op)
rules.add_perm('lock8.view_reservation_transitions', (
        is_admin_of_lock8 |
        is_at_least_fleet_op_of_descendant_organization |
        (is_at_least_renter & is_owned_by)))

# SharedSecret
rules.add_perm('lock8.add_sharedsecret',
               is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.view_sharedsecret', view_shared_secret_perm)
rules.add_perm('lock8.change_sharedsecret', is_superuser)
rules.add_perm('lock8.delete_sharedsecret', is_superuser)

# TermsOfService
rules.add_perm('lock8.view_termsofservice',
               is_superuser | is_open_fleet | is_member_of_closed_fleet)
rules.add_perm('lock8.add_termsofservice', admin_user_or_fleet_op)
rules.add_perm('lock8.change_termsofservice', admin_user_or_fleet_op)
rules.add_perm('lock8.delete_termsofservice', admin_user_or_fleet_op)

# TermsOfServiceVersion
rules.add_perm('lock8.view_termsofserviceversion', admin_user_or_fleet_op)
rules.add_perm('lock8.add_termsofserviceversion', admin_user_or_fleet_op)
rules.add_perm('lock8.change_termsofserviceversion', admin_user_or_fleet_op)
rules.add_perm('lock8.delete_termsofserviceversion', admin_user_or_fleet_op)

# Tracking
rules.add_perm('lock8.view_tracking', admin_user_or_fleet_op)
rules.add_perm('lock8.add_tracking', is_superuser)
rules.add_perm('lock8.change_tracking', is_superuser)
rules.add_perm('lock8.delete_tracking', is_superuser)
rules.add_perm('lock8.view_tracking_transitions', admin_user_or_fleet_op)

# ReadonlyTracking (change is used for admin changelist).
rules.add_perm('lock8.view_readonlytracking',
               is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.change_readonlytracking',
               is_superuser | is_admin_of_lock8)

# Trip
rules.add_perm('lock8.view_trip', admin_user_or_fleet_op |
               is_renting_the_attached_bicycle)

# SubscriptionPlan
rules.add_perm('lock8.view_subscriptionplan',
               is_superuser | is_open_fleet | is_member_of_closed_fleet)
rules.add_perm('lock8.add_subscriptionplan',
               is_superuser | is_at_least_fleet_op_or_admin_of_lock8)
rules.add_perm('lock8.change_subscriptionplan', admin_user_or_fleet_op)
rules.add_perm('lock8.delete_subscriptionplan', admin_user_or_fleet_op)
rules.add_perm('lock8.subscribe_user_subscriptionplan',
               is_superuser |
               (is_eligible_for_plan & (
                   is_open_fleet | (
                       is_member_of_closed_fleet & is_at_least_renter))))
rules.add_perm('lock8.unsubscribe_user_subscriptionplan',
               is_superuser |
               (is_open_fleet |
                (is_member_of_closed_fleet & is_at_least_renter)))
rules.add_perm('lock8.view_subscriptionplan_transitions',
               admin_user_or_fleet_op)

# PlanPass
rules.add_perm('lock8.view_planpass', admin_user_or_fleet_op)
rules.add_perm('lock8.add_planpass', admin_user_or_fleet_op)
rules.add_perm('lock8.change_planpass', admin_user_or_fleet_op)
rules.add_perm('lock8.delete_planpass', admin_user_or_fleet_op)

# User
rules.add_perm('lock8.view_user',
               admin_user_or_fleet_op |
               (is_self & rules.predicates.is_authenticated))
rules.add_perm('lock8.add_user', is_superuser | is_admin_of_lock8)
rules.add_perm('lock8.change_user',
               is_superuser | (is_self & is_local & is_at_least_renter) |
               is_admin_of_lock8)
rules.add_perm('lock8.delete_user',
               is_superuser | (is_self & is_local & is_at_least_renter) |
               is_admin_of_lock8)
rules.add_perm('lock8.disable_user', admin_user_or_fleet_op)
rules.add_perm('lock8.enable_user', admin_user_or_fleet_op)
rules.add_perm('lock8.view_user_transitions', is_superuser)
rules.add_perm('lock8.change_password_user',
               is_superuser | (is_self & is_local & is_at_least_renter) |
               is_admin_of_lock8)
rules.add_perm('lock8.reset_refresh_tokens_user', is_superuser |
               (is_self & rules.predicates.is_authenticated))

# UserProfile
userprofile_perm = (admin_user_or_fleet_op |
                    (is_self & is_at_least_renter))
rules.add_perm('lock8.view_userprofile', userprofile_perm)
rules.add_perm('lock8.add_userprofile', userprofile_perm)
rules.add_perm('lock8.change_userprofile', userprofile_perm)
rules.add_perm('lock8.delete_userprofile', userprofile_perm)
rules.add_perm('lock8.view_userprofile_transitions', userprofile_perm)

# Task
task_base_perm = admin_user_or_fleet_op
rules.add_perm('lock8.add_task', task_base_perm | is_mechanic)
rules.add_perm('lock8.view_task', task_base_perm | is_assigned_to_group &
               has_task_viewable_role)
rules.add_perm('lock8.change_task', task_base_perm | is_assigned_to_group)
rules.add_perm('lock8.delete_task', task_base_perm | is_assigned_to_group)
rules.add_perm('lock8.assign_task', task_base_perm | is_assigned_to_group)
rules.add_perm('lock8.unassign_task', task_base_perm | is_assigned_to_group)
rules.add_perm('lock8.complete_task', task_base_perm | is_assigned_to_group)
rules.add_perm('lock8.view_task_transitions', task_base_perm |
               is_assigned_to_group & has_task_viewable_role)

# Zone
rules.add_perm('lock8.add_zone',
               is_superuser |
               is_at_least_fleet_op_or_admin_of_lock8)
rules.add_perm('lock8.view_zone',
               is_superuser |
               (is_member_of_closed_fleet & is_at_least_renter) |
               (is_closed_fleet & (
                is_at_least_fleet_op_of_descendant_organization) |
                (rules.predicates.is_authenticated & is_open_fleet &
                    is_at_least_renter)))
rules.add_perm('lock8.change_zone', admin_user_or_fleet_op)
rules.add_perm('lock8.delete_zone', admin_user_or_fleet_op)
rules.add_perm('lock8.view_zone_transitions', admin_user_or_fleet_op)

# Debug views.
rules.add_perm('lock8.view_debug', is_superuser | is_admin_of_lock8)

# Predictions
rules.add_perm('lock8.view_predictions',
               is_superuser | is_admin_of_lock8 |
               rules.predicates.is_authenticated &
               can_access_analytics_feature)

rules.add_perm('lock8.stripe_oauth', is_at_least_fleet_op_or_admin_of_lock8)
