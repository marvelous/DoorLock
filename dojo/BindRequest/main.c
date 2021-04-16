#include <stdio.h>
#define BIND_RESPONSE 0
// header -------------
// 30 packet ldap
// 0c size du message

//  message content
// 02 (int)
// 01 taille
// 01 valeur

// data -------------
// 61 (type) [bind response]
// 07 (taille)

// 0a (type) [enum]
// 01 (taille)
// 00 (valeur) [=success]

// 04 (type: string) [  matchedDN     LDAPDN,]
// 00 (taille)

// 04 (type: string) [errorMessage  ErrorMessage]
// 00 (taille)

int main() {
  printf("%x", 0xf2);
  return 0;
}

// LDAPResult ::= SEQUENCE {
//   resultCode
//     ENUMERATED {success(0), operationsError(1), protocolError(2),
//                 timeLimitExceeded(3), sizeLimitExceeded(4), compareFalse(5),
//                 compareTrue(6), authMethodNotSupported(7),
//                 strongAuthRequired(8),
//                 -- 9 reserved
//                 referral(10),-- new-- adminLimitExceeded(11),-- new--
//                 unavailableCriticalExtension(12),-- new--
//                 confidentialityRequired(13),-- new--
//                 saslBindInProgress(14),-- new-- noSuchAttribute(16),
//                 undefinedAttributeType(17), inappropriateMatching(18),
//                 constraintViolation(19), attributeOrValueExists(20),
//                 invalidAttributeSyntax(21),
//                 -- 22-31 unused
//                 noSuchObject(32), aliasProblem(33),
//                 invalidDNSyntax(34),
//                 -- 35 reserved for undefined isLeaf
//                 aliasDereferencingProblem(36),
//                 -- 37-47 unused
//                 inappropriateAuthentication(48), invalidCredentials(49),
//                 insufficientAccessRights(50), busy(51), unavailable(52),
//                 unwillingToPerform(53),
//                 loopDetect(54),
//                 -- 55-63 unused
//                 namingViolation(64), objectClassViolation(65),
//                 notAllowedOnNonLeaf(66), notAllowedOnRDN(67),
//                 entryAlreadyExists(68),
//                 objectClassModsProhibited(69),
//                 -- 70 reserved for CLDAP
//                 affectsMultipleDSAs(71),-- new--
//                 -- 72-79 unused
//                 other(80),
// 		canceled(118), noSuchOperation(119), tooLate(120),
// cannotCancel(121) -- RFC 3909
// 		},
//   -- 81-90 reserved for APIs
//   matchedDN     LDAPDN,
//   errorMessage  ErrorMessage,
//   referral      [3]  Referral OPTIONAL
// }
