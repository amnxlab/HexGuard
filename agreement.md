# HexGuard-Hunt Project Agreement

This Project Agreement (the “Agreement”) sets out the scope, responsibilities, limitations, and
delivery expectations for the development of HexGuard-Hunt, a Linux-based desktop security
testing system that uses AI-driven decision-making to automate limited web vulnerability
discovery through controlled tool orchestration. A software development agreement should
clearly define the project scope, services, deliverables, and responsibilities of both parties, which
is the structure followed in this document.

**Project Purpose**

The purpose of HexGuard-Hunt is to deliver a focused security testing system for web
applications, specifically REST APIs, using a constrained and research-oriented architecture. The
project is intentionally limited in scope so that the system remains technically feasible, clearly
novel, and manageable in implementation rather than expanding into a broad offensive security
platform.

**System Description**

HexGuard-Hunt will be delivered as a Linux-based desktop application. The system will use
HexStrike AI Agent through the Model Context Protocol (MCP) and will rely on an external
large language model service, such as GPT or Claude, for reasoning tasks only. The client must
provide an active subscription and valid API access for the selected LLM service, since API
agreements commonly place responsibility for licensed access and permitted use on the client or
licensee side.

Within the system architecture, the LLM will be used only to interpret outputs, support
reasoning, and assist in adjusting scoring logic. The LLM will not be responsible for direct tool
execution, autonomous exploitation beyond the approved flow, or any unrestricted attack
behavior.

**Scope of Work**

The system will operate only against web applications that expose REST APIs over HTTP or
HTTPS. It will process JSON-based endpoints only and will use Bearer Token authentication
only. The project does not include user interface crawling, browser automation, mobile targets,
IoT targets, or RF-related testing.

The functional scope of the system is limited to endpoint discovery, parameter extraction,
endpoint scoring, parameter fuzzing, injection detection, IDOR-oriented access control mutation,
validation of findings, and generation of a final report. The core vulnerability classes included in
the project are SQL Injection, reflected or stored Cross-Site Scripting, and Insecure Direct Object
Reference. Supporting checks are limited to basic misconfigurations, such as exposed debug
endpoints or exposed paths.


**Core Technical Logic**

The novelty of the system is confined to three mandatory components: the Decision Engine, the
Feedback Loop, and limited Attack Chaining. No additional novelty claims, auxiliary automation
tracks, or unrelated scanning modules are included in the agreed scope.

The Decision Engine will be state-based rather than prompt-based. Its state representation will
include the endpoint, parameters, observed response patterns, and authentication state. The
engine will score and prioritize targets using metrics such as parameter entropy, response
variance, and error patterns, then decide whether an endpoint should be ignored, fuzzed further,
or escalated to injection testing.

The Feedback Loop will update endpoint scores after each action and reduce the search space
over time. Confirmed vulnerabilities will act as positive signals, while noisy or uninformative
outcomes will reduce priority. The role of the LLM in this loop is limited to interpreting results
and recommending weight adjustments rather than directly controlling the tools.

Attack Chaining is intentionally restricted to three narrow cases. The first permitted chain is
IDOR leading to sensitive data exposure. The second permitted chain is IDOR leading to basic
role escalation. The third permitted chain is XSS leading to conceptual validation of session or
token exposure. No other chaining scenarios are included.

**Tooling and Execution Flow**

The approved tool layer is limited to ffuf for endpoint discovery, sqlmap for SQL injection
testing or exploitation within the approved scope, and Burp Suite for validation. The agreement
does not include additional tools unless their use directly supports the Decision Engine, the
Feedback Loop, or the approved chaining logic.

The execution flow of the system will follow a fixed sequence consisting of endpoint discovery,
parameter extraction, endpoint scoring, target selection, fuzzing, score updates through feedback,
threshold-based injection testing, IDOR mutation testing, validation of findings, allowed
chaining attempts only, and final report generation. This sequencing is part of the core scope and
is not intended to be replaced with unrestricted brute-force behavior.

**Out of Scope**

The following are expressly excluded from this Agreement: CSRF testing, business logic
vulnerabilities, race conditions, advanced authentication bypass, full exploit development, SSRF
chains, RCE chains, complex multi-stage exploitation, frontend testing, browser-driven
interaction, and any vulnerability category outside the defined scope. Any feature, module, or
workflow that does not directly serve the Decision Engine, Feedback Loop, or limited Attack
Chaining model is also excluded.


This Agreement also excludes academic support work beyond direct project delivery. The
developer is not responsible for preparing presentations, slide decks, books, formal graduation-
project booklets, or extended academic documentation unless separately agreed in writing.

**Delivery Standard**

The project will be considered complete when the system demonstrates intelligent endpoint
selection rather than brute-force behavior, reduces request volume relative to a baseline
approach, identifies at least one of the approved vulnerability classes, performs at least one
allowed chain based on the defined chaining scope, and reduces false positives through
validation. Clear project completion criteria are a standard part of software development
agreements because they establish the expected deliverables and ending point for the work.

The final delivery will consist of a working Linux desktop application and one explanation
session covering the system architecture, execution flow, and operational use. The delivery
obligation is limited to presenting the project and explaining the implemented system.

**Client Responsibilities**

The client or student team is responsible for providing valid LLM API access for the selected
service and for maintaining any required subscription during development, testing, and
demonstration. The client is also responsible for preparing the target environment, system
prerequisites, and any access credentials required for the approved testing scope.

The client or student team is further responsible for studying the included vulnerability classes
before the explanation session. This means the students are expected to understand the
fundamentals of SQL Injection, XSS, and IDOR in advance. The explanation session is intended
to focus on the system design, workflow, and tool usage rather than teaching vulnerability theory
from the beginning.

**Developer Responsibilities**

The developer is responsible for designing, implementing, and delivering the system in
accordance with the defined scope in this Agreement. The developer will explain how the system
works, how it is executed, and how its core modules interact, especially the Decision Engine,
Feedback Loop, and limited Attack Chaining logic.

The developer is not responsible for teaching a full cybersecurity curriculum, preparing students
for oral examinations beyond the delivered explanation, or producing non-agreed academic
materials. The developer is also not responsible for service interruptions, quota limits, billing
issues, or policy restrictions imposed by the external LLM provider selected by the client, since
such access depends on third-party API terms and subscription availability.


**Use Limitation**

HexGuard-Hunt is delivered for educational and research purposes within the approved project
context. The system is not intended to serve as an unrestricted offensive platform, and no
responsibility is accepted for misuse outside the agreed academic or research scope.

**Change Control**

Any request to expand the vulnerability classes, add new tools, support UI or browser-based
testing, include advanced exploitation paths, or create academic presentation materials will be
treated as a separate change request. Standard software development agreements commonly
separate the agreed scope from later additions, and any such additions should be documented
independently rather than assumed to be included in the base engagement.

**Acceptance**

By approving this Agreement, the parties confirm that the project is intentionally restricted to the
stated scope and that delivery is limited to the implemented system and its explanation. Any
expectation beyond these terms, including presentation preparation, project-book writing, or
broader cybersecurity instruction, is outside the present Agreement unless later added through a
separate written amendment.

**_Ahmed Amin_**

**_R&D Engineer_**