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

class ProjectNotFoundError(Exception):
  pass

class ProjectConflictError(Exception):
  pass

class SourceConflictError(Exception):
  pass

class SourceCredentialError(Exception):
  pass

class SourceNotFoundError(Exception):
  pass

class IncidentNotFoundError(Exception):
  pass

class InvalidIncidentTransitionError(Exception):
  pass
