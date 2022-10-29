from rest_framework.routers import APIRootView, DefaultRouter
from rest_framework_nested.routers import NestedSimpleRouter

from .views import (
    AddressViewSet, AffiliationViewSet, AlertViewSet, AxaLockViewSet,
    BicycleModelMaintenanceRuleViewSet, BicycleModelViewSet,
    BicycleTypeViewSet, BicycleViewSet, ClientAppViewSet,
    FeedbackCategoryViewSet, FeedbackViewSet, FirmwareViewSet,
    InvitationViewSet, LockFirmwareUpdateViewSet, LockViewSet, MetricsViewSet,
    NotificationMessageViewSet, OrganizationViewSet, ParentMetricsViewSet,
    ParentPredictionsViewSet, PhotoViewSet, PlanPassViewSet,
    PredictionsViewSet, PricingSchemeViewSet, RefreshTokenViewSet,
    RentalSessionViewSet, RentingSchemeViewSet, ReservationViewSet,
    SubscriptionPlanViewSet, SupportTicketViewSet, TaskViewSet,
    TermsOfServiceVersionViewSet, TermsOfServiceViewSet, TripViewSet,
    UserProfileViewSet, UserViewSet, ZoneViewSet,
)


class NoaApiView(APIRootView):
    pass


class Router(DefaultRouter):
    APIRootView = NoaApiView


router = Router()
router.register(r'addresses', AddressViewSet, basename='address')
router.register(r'affiliations', AffiliationViewSet, basename='affiliation')
router.register(r'alerts', AlertViewSet, basename='alert')
router.register(r'axa_locks', AxaLockViewSet, basename='axa_lock')
router.register(r'bicycle_models', BicycleModelViewSet,
                basename='bicycle_model')
router.register(r'bicycle_types', BicycleTypeViewSet, basename='bicycle_type')
router.register(r'bicycles', BicycleViewSet, basename='bicycle')
router.register(r'client_apps', ClientAppViewSet, basename='client_app')
router.register(r'feedback_categories', FeedbackCategoryViewSet,
                basename='feedback_category')
router.register(r'feedbacks', FeedbackViewSet, basename='feedback')
router.register(r'firmwares', FirmwareViewSet, basename='firmware')
router.register(r'invitations', InvitationViewSet, basename='invitation')
router.register(r'lock_firmware_updates', LockFirmwareUpdateViewSet,
                basename='lock_firmware_update')
router.register(r'locks', LockViewSet, basename='lock')
router.register(r'notification_messages', NotificationMessageViewSet,
                basename='notification_message')
router.register(r'organizations', OrganizationViewSet,
                basename='organization')
router.register(r'photos', PhotoViewSet, basename='photo')
router.register(r'plan_passes', PlanPassViewSet, basename='plan_pass')
router.register(r'pricing_schemes', PricingSchemeViewSet,
                basename='pricing_scheme')
router.register(r'refresh_tokens', RefreshTokenViewSet,
                basename='refresh_token')
router.register(r'rental_sessions', RentalSessionViewSet,
                basename='rental_session')
router.register(r'renting_schemes', RentingSchemeViewSet,
                basename='renting_scheme')
router.register(r'reservations', ReservationViewSet, basename='reservation')
router.register(r'subscription_plans', SubscriptionPlanViewSet,
                basename='subscription_plan')
router.register(r'support_tickets', SupportTicketViewSet,
                basename='support_ticket')
router.register(r'tasks', TaskViewSet, basename='task')
router.register(r'terms_of_service_versions', TermsOfServiceVersionViewSet,
                basename='terms_of_service_version')
router.register(r'terms_of_services', TermsOfServiceViewSet,
                basename='terms_of_service')
router.register(r'trips', TripViewSet, basename='trip')
router.register(r'users', UserViewSet, basename='user')
router.register(r'zones', ZoneViewSet, basename='zone')
router.register(r'metrics', ParentMetricsViewSet, basename='metric')
router.register(r'predictions', ParentPredictionsViewSet,
                basename='prediction')

# nested routes
bicycle_model_nested_router = NestedSimpleRouter(
    router, r'bicycle_models',
    lookup='parent_lookup'
)
bicycle_model_nested_router.register(
    r'maintenance_rules',
    BicycleModelMaintenanceRuleViewSet,
    basename='maintenance_rule'
)
user_nested_router = NestedSimpleRouter(
    router,
    r'users',
    lookup='parent_lookup'
)
user_nested_router.register(
    r'profiles',
    UserProfileViewSet,
    basename='user_profile'
)
metrics_nested_router = NestedSimpleRouter(
    router,
    r'metrics',
    lookup='metric'
)
metrics_nested_router.register(
    r'values',
    MetricsViewSet,
    basename='metric_value'
)
predictions_nested_router = NestedSimpleRouter(
    router,
    r'predictions',
    lookup='prediction'
)
predictions_nested_router.register(
    r'values',
    PredictionsViewSet,
    basename='prediction_value'
)
router.urls.extend(
    bicycle_model_nested_router.urls +
    user_nested_router.urls +
    metrics_nested_router.urls +
    predictions_nested_router.urls
)

router.urls.sort(key=lambda x: x.pattern.name)
