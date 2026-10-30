class InvalidCredentialsError(Exception):
  pass

class EmailDeliveryError(Exception):
  pass

class RateLimitExceededError(Exception):
  pass

class InvalidOTPError(Exception):
  pass

class OTPChallengeError(Exception):
  pass

class OTPAttemptsExceededError(Exception):
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

class SourceConfigurationError(Exception):
  pass

class LokiIntegrationError(Exception):
  def __init__(self, status_code: int, detail: str):
    self.status_code = status_code
    self.detail = detail
    super().__init__(detail)

class TraceIntegrationError(Exception):
  def __init__(self, status_code: int, detail: str):
    self.status_code = status_code
    self.detail = detail
    super().__init__(detail)

class DockerIntegrationError(Exception):
  def __init__(self, status_code: int, detail: str):
    self.status_code = status_code
    self.detail = detail
    super().__init__(detail)

class DockerContainerNotFoundError(Exception):
  pass

class SourceNotFoundError(Exception):
  pass

class IncidentNotFoundError(Exception):
  pass

class InvalidIncidentTransitionError(Exception):
  pass

class GitHubIntegrationError(Exception):
  def __init__(self, status_code: int, detail: str):
    self.status_code = status_code
    self.detail = detail
    super().__init__(detail)

class GitHubNotFoundError(Exception):
  pass

class GitHubConflictError(Exception):
  pass
