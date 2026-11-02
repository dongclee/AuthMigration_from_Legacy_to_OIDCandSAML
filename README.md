# AuthMigration_from_Legacy_to_OIDCandSAML

# DNGRMS 는 나의 샘플 웹 어플리케이션 이라고 가정합니다.

# DNGRMS 인증 현대화 고객 요약
## Legacy Local ID/PW에서 Microsoft Entra ID OIDC·SAML 인증으로의 단계적 전환

### 1. 추진 목적

DNGRMS의 기존 업무 기능, 사용자 데이터 및 애플리케이션 권한 체계를 유지하면서, 애플리케이션이 직접 관리하던 Local ID/PW 인증을 Microsoft Entra ID 기반의 OIDC 또는 SAML 인증으로 단계적으로 전환하는 방안을 실제 데모 환경에서 검증했습니다.

이번 구현은 기존 인증을 즉시 제거하는 Big-Bang 방식이 아니라, **Local → Dual → OIDC/SAML → 제한적 Local Credential Retirement** 순서로 전환하고, 필요 시 이전 인증 모드로 복구할 수 있도록 설계했습니다.

---

### 2. 구현 및 검증 결과

#### Legacy Baseline

- ASP.NET Core 8 및 SQLite 기반 DNGRMS 애플리케이션
- Local ID/PW, 단방향 Password Hash 및 Cookie Session 유지
- Admin/User Role과 인증 성공·실패·로그아웃 Audit 기록
- Azure App Service Linux 배포 및 SQLite 데이터 영속성 검증

#### OIDC Migration

- Microsoft Entra App Registration과 Enterprise Application 구성
- Redirect URI, Logout URI, Client Credential 및 Pilot User Assignment 검증
- Authorization Code Flow와 PKCE 기반 실제 OIDC 로그인 성공
- Issuer, Audience, Signature 검증 후 DNGRMS Application Session 생성
- Entra Object ID를 이용한 기존 DNGRMS 사용자 연결
- Safe Claims, Role 분리 및 OIDC Logout 검증

#### SAML Migration

- Non-gallery Enterprise Application과 SAML SSO 구성
- Entity ID, ACS URL, Sign-on URL 및 Pilot User Assignment 검증
- Token Signing Certificate와 Federation Metadata 기반 Trust 구성
- SP-Initiated Login, SAML Response 및 ACS Callback 성공
- Signature, Issuer, Audience 및 유효 시간 검증
- Object ID 기반 Cross-protocol Identity Linking 확인

---

### 3. 핵심 설계 원칙

**인증 프로토콜과 업무 사용자·권한을 분리했습니다.**

Local은 Password Hash, OIDC는 Authorization Code와 ID Token, SAML은 서명된 XML Assertion을 사용하지만, 모든 인증 방식은 최종적으로 동일한 **DNGRMS 사용자, Role/Profile 및 Application Session**으로 연결됩니다.

Microsoft Entra ID는 사용자의 신원을 인증하고, 실제 업무 권한은 DNGRMS의 Application Role이 결정합니다. 따라서 Entra 관리자 계정으로 인증하더라도 **DNGRMS Admin 권한이 자동으로 부여되지 않습니다.**

비밀번호, Password Hash 값, Client Secret, ID/Access/Refresh Token, Private Key 및 Raw SAML Assertion은 고객 증적에 포함하지 않고, 인증 방식·사용자 매핑·Role·Issuer 등 검증에 필요한 최소 정보만 기록했습니다.

---

### 4. Cutover와 Rollback 검증

- 일반 사용자 `dngrms-user`의 Local Login을 정책적으로 차단
- 비상용 `dngrms-admin`의 Break-glass Local Credential은 보존
- OIDC Mode에서는 Local 인증 경로 전체를 차단
- OIDC를 기본 인증 방식으로 전환한 후 실제 로그인과 사용자 매핑 검증
- OIDC에서 Dual Mode로 Rollback한 후 **Local·OIDC·SAML 세 경로 모두 실제 로그인 성공**
- Rollback 후에도 일반 사용자의 Local Login 차단 정책 유지
- 최종 상태, 사용자 매핑 및 인증 Audit을 **Secret-free JSON Evidence**로 생성

---

### 5. 고객 선택 가이드

#### OIDC 권장 환경

- 현대적인 Web/Application Architecture
- Authorization Code Flow, PKCE 및 API 확장 필요
- 표준 Callback과 Token 기반 통합을 선호하는 환경

#### SAML 권장 환경

- 기존 Enterprise Application 또는 상용 솔루션과의 연계
- Entity ID, ACS 및 Federation Metadata 기반 표준이 필요한 환경
- 인증서 기반 Trust와 기존 SAML 운영 체계를 보유한 환경

두 방식 모두 Microsoft Entra ID를 인증 주체로 사용하며, **DNGRMS의 사용자·업무 Role·데이터 모델은 유지할 수 있습니다.**

최종 선택은 애플리케이션 지원 범위, 기존 표준, 인증서·Credential 운영 역량 및 장애 대응 체계를 기준으로 결정해야 합니다.

---

# 최종 결론

**DNGRMS의 Legacy Local 인증에서 Microsoft Entra ID OIDC 및 SAML 인증으로 전환하는 기술 경로와 통제된 Rollback 경로가 실제 데모를 통해 검증되었습니다.**

애플리케이션과 업무 데이터를 재구축하지 않고 인증 계층을 단계적으로 교체할 수 있으며, OIDC와 SAML이 동일한 Entra Object ID 및 기존 DNGRMS 사용자로 수렴하는 것도 확인했습니다.

다만 이번 결과는 **기술 구현 및 데모 검증 완료**를 의미하며, 프로덕션 전환을 위해서는 실제 URL 확정, Credential·인증서 순환, 역할 및 그룹 할당 거버넌스, 모니터링, 변경 승인, Rollback Rehearsal과 Cleanup 검증을 별도 운영 Gate로 완료해야 합니다.




# Let’s assume DNGRMS is my sample web application.

# DNGRMS Authentication Modernization - Customer Summary
## Phased Migration from Legacy Local ID/Password Authentication to Microsoft Entra ID OIDC and SAML

### 1. Objective

This demonstration validates a phased approach for migrating DNGRMS from application-managed Local ID/Password authentication to Microsoft Entra ID-based OIDC or SAML authentication while preserving the existing business functionality, user data, and application authorization model.

Rather than immediately removing the legacy authentication mechanism through a big-bang migration, the solution supports a controlled transition:

**Local → Dual → OIDC/SAML → Restricted Local Credential Retirement**

The architecture also provides a controlled rollback path so that the authentication mode can be restored when operational or emergency conditions require it.

---

### 2. Implementation and Validation Results

#### Legacy Baseline

- DNGRMS application based on ASP.NET Core 8 and SQLite
- Local ID/Password authentication with one-way password hashing
- Application-managed cookie session
- Admin/User application roles
- Authentication success, failure, and logout audit records
- Deployment to Azure App Service on Linux
- SQLite data persistence validation

#### OIDC Migration

- Microsoft Entra App Registration and Enterprise Application configuration
- Redirect URI and Logout URI configuration
- Client Credential and Pilot User Assignment validation
- Successful OIDC sign-in using Authorization Code Flow with PKCE
- Issuer, Audience, and Signature validation
- DNGRMS application session creation after successful authentication
- Existing DNGRMS user mapping using the Microsoft Entra Object ID
- Safe Claims and application role separation
- OIDC logout validation

#### SAML Migration

- Non-gallery Enterprise Application and SAML SSO configuration
- Entity ID, ACS URL, and Sign-on URL configuration
- Token Signing Certificate and Federation Metadata-based trust
- Pilot User Assignment
- Successful SP-Initiated SAML sign-in
- SAML Response processing through the ACS endpoint
- Signature, Issuer, Audience, and validity-time validation
- Cross-protocol Identity Linking using the Microsoft Entra Object ID

---

### 3. Core Architecture Principles

**Authentication protocols are separated from business users and application authorization.**

Each authentication method uses a different trust mechanism:

- **Local:** Password Hash
- **OIDC:** Authorization Code and ID Token
- **SAML:** Digitally Signed XML Assertion

However, all authentication methods ultimately converge on the same **DNGRMS user identity, Role/Profile model, and application session**.

Microsoft Entra ID authenticates the user's identity, while the DNGRMS Application Role determines the user's business authorization.

As a result, authenticating with a Microsoft Entra administrative account does **not** automatically grant DNGRMS Admin privileges.

Sensitive security artifacts are intentionally excluded from customer evidence, including:

- Raw passwords
- Password hash values
- Client Secrets
- ID Tokens
- Access Tokens
- Refresh Tokens
- Private Keys
- Raw SAML Assertions

Only the minimum information required to validate authentication, identity mapping, application roles, and issuer relationships is retained as evidence.

---

### 4. Cutover and Rollback Validation

The demonstration validated the following migration controls:

- Local login for the standard `dngrms-user` account can be explicitly disabled by policy.
- The `dngrms-admin` account can retain a restricted Local Credential for break-glass access.
- Local authentication is blocked while DNGRMS operates in OIDC-only mode.
- OIDC was successfully configured as the default authentication method, followed by successful sign-in and existing-user mapping.
- DNGRMS was successfully rolled back from OIDC mode to Dual mode without deleting application data.
- After rollback to Dual mode, **Local, OIDC, and SAML authentication were all successfully validated**.
- The standard user's Local Login restriction remained effective after rollback.
- Final application state, user mappings, and authentication audit records can be exported as secret-free JSON evidence.

This design demonstrates that rollback does not mean indiscriminately re-enabling every legacy credential. Local authentication eligibility remains controlled at the individual user level.

---

### 5. Customer Selection Guide

#### OIDC Is Recommended When

- The application follows a modern Web/Application architecture.
- Authorization Code Flow and PKCE are required.
- Future API integration or token-based architecture is expected.
- Standard callback and modern identity patterns are preferred.

#### SAML Is Recommended When

- Integration with an existing enterprise application or commercial solution is required.
- The application already supports Entity ID, ACS, and Federation Metadata-based federation.
- The organization operates an established certificate-based trust model.
- Existing SAML operational practices need to be preserved.

Both approaches use Microsoft Entra ID as the identity provider while allowing the existing **DNGRMS user, application role, and business data models to remain intact**.

The final protocol selection should therefore consider:

- Application protocol support
- Existing enterprise identity standards
- Credential and certificate lifecycle management
- Operational capabilities
- Troubleshooting and recovery requirements
- Future application and API architecture

---

# Conclusion

**The demonstration successfully validated a technical migration path from DNGRMS Legacy Local authentication to Microsoft Entra ID-based OIDC and SAML authentication, including a controlled rollback path.**

The authentication layer can be modernized incrementally without rebuilding the application, business data, or existing authorization model.

The demonstration also validated that OIDC and SAML identities can converge on the same existing DNGRMS user through Microsoft Entra Object ID-based identity linking, allowing the authentication protocol to change while preserving the application's internal user identity and business authorization.

The demonstration results represent completion of the **technical implementation and validation phase**, not an unconditional production-readiness declaration.

Before production cutover, additional operational gates should be completed, including:

- Final production URL configuration
- Credential and certificate lifecycle and rotation procedures
- Role and group assignment governance
- Monitoring and operational alerting
- Formal change approval
- Rollback rehearsal
- Cleanup and post-migration verification

The resulting architecture provides a practical foundation for migrating legacy application authentication to Microsoft Entra ID while maintaining application continuity, controlled authorization, rollback capability, and verifiable authentication evidence.
