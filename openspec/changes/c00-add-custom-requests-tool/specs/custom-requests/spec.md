# Custom Requests Delta

## ADDED Requirements

### Requirement: Arbitrary HTTP Request Dispatch
The custom requests tool SHALL send exactly one HTTP request per invocation using an
operator-chosen method, target URL, custom headers, and an optional request body, and SHALL
capture the full response for inspection.

#### Scenario: Sends a request with the chosen method and headers
- **GIVEN** a target URL, a chosen HTTP method, and one or more custom headers
- **WHEN** the operator invokes the tool
- **THEN** it SHALL issue a single request to that URL using the chosen method and headers
- **AND** it SHALL capture the response status, response headers, response body, and the
  round-trip time

#### Scenario: Sends a request body when provided
- **GIVEN** a method that carries a body and an operator-supplied body
- **WHEN** the operator invokes the tool
- **THEN** the request SHALL carry the supplied body

#### Scenario: Records the redirect outcome
- **GIVEN** a target that responds with one or more redirects to a request configured to
  follow redirects
- **WHEN** the tool sends the request
- **THEN** the captured result SHALL include the final URL and final status after following
  the redirects
- **AND** it SHALL include a count of the redirects that were followed

#### Scenario: Transport failure is reported, not fatal
- **GIVEN** a target that is unreachable or does not respond within the configured timeout
- **WHEN** the tool sends the request
- **THEN** it SHALL return a result that reports the error
- **AND** it SHALL NOT crash the surrounding process

#### Scenario: TLS verification is on unless explicitly disabled
- **GIVEN** no explicit instruction to skip TLS verification
- **WHEN** the tool sends a request over TLS
- **THEN** it SHALL verify the target's TLS certificate
- **AND** verification SHALL be disabled only when the operator explicitly opts out for that
  invocation

### Requirement: Optional Bearer And Cookie Authentication
The tool SHALL support attaching a bearer token and/or session cookies to a request, where
each is independent and optional, and SHALL send a request with no authentication when
neither is supplied.

#### Scenario: Bearer token attached as authorization
- **GIVEN** an operator-supplied bearer token
- **WHEN** the tool sends the request
- **THEN** the request SHALL carry an authorization header presenting that token as a bearer
  credential

#### Scenario: Session cookies attached
- **GIVEN** an operator-supplied cookie string
- **WHEN** the tool sends the request
- **THEN** the request SHALL carry a cookie header conveying those cookies

#### Scenario: Token and cookies together
- **GIVEN** both a bearer token and a cookie string
- **WHEN** the tool sends the request
- **THEN** the request SHALL carry both the authorization header and the cookie header

#### Scenario: Keyless request requires no authentication
- **GIVEN** no bearer token and no cookie string
- **WHEN** the operator invokes the tool
- **THEN** the request SHALL be sent without any added authentication
- **AND** the invocation SHALL succeed on the basis of the response alone

### Requirement: Response Signal Analysis
The tool SHALL inspect the captured response and surface notable, advisory security signals
that guide manual follow-up, without classifying them as confirmed vulnerabilities.

#### Scenario: Flags information-disclosure headers
- **GIVEN** a response that includes a header disclosing server software, technology stack,
  or source-path information
- **WHEN** the tool analyzes the response
- **THEN** it SHALL surface a signal identifying the disclosing header and its value

#### Scenario: Flags missing security headers
- **GIVEN** a response that omits one or more expected response-hardening security headers
- **WHEN** the tool analyzes the response
- **THEN** it SHALL surface a signal for each expected security header that is absent

#### Scenario: Flags error-detail leakage in the body
- **GIVEN** a response whose body contains stack-trace or debug indicators
- **WHEN** the tool analyzes the response
- **THEN** it SHALL surface a signal noting potential error-detail leakage

#### Scenario: Clean response yields no signals
- **GIVEN** a response that carries the expected security headers, discloses no version or
  technology banners, and contains no error detail
- **WHEN** the tool analyzes the response
- **THEN** it SHALL surface no signals

### Requirement: Shared Surface And Output Formats
The tool SHALL be usable identically from the command-line and web surfaces from one shared
implementation, and SHALL render its outcome in both a human-readable form and a structured
JSON form.

#### Scenario: Same outcome from either surface
- **GIVEN** an identical request specification
- **WHEN** the tool is invoked from the command-line surface and from the web surface
- **THEN** both SHALL produce the same captured response and the same analysis signals

#### Scenario: Human-readable output
- **WHEN** the human-readable output form is selected
- **THEN** the tool SHALL render the request, the response status, the response headers, a
  preview of the response body, and any analysis signals as readable text

#### Scenario: JSON output
- **WHEN** the JSON output form is selected
- **THEN** the tool SHALL emit a single structured document containing the request, the
  captured response, and the analysis signals
- **AND** the document SHALL be machine-parseable
