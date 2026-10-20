class InvalidCredentialsError(Exception):
  pass

class EmailDeliveryError(Exception):
  pass

class RateLimitExceededError(Exception):
  pass

class InvalidOTPError(Exception):
  pass

class InvalidRefreshTokenError(Exception):
  pass

class PermissionDeniedError(Exception):
  pass

class InvitationTargetError(Exception):
  pass

class OrganisationConflictError(Exception):
  pass

class ProjectTargetError(Exception):
  pass

class ProjectNotFoundError(Exception):
  pass

class ProjectConflictError(Exception):
  pass
