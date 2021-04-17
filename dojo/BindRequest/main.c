#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define BIND_RESPONSE "\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00"

enum ldap_id {
  // Base types
  Bool = 0x01,
  Integer = 0x02,
  String = 0x04,
  Enum = 0x0a,

  Attribute = 0x30,

  // Op(erations)
  BindRequest = 0x60,
  BindResponse,
  UnbindRequest,
  SearchRequest,
  SearchResultEntry,
  SearchResultDone,
  SearchResultReference,
  ModifyRequest,
  ModifyResponse,
  AddRequest,
  AddResponse,
  DelRequest,
  DelResponse,
  ModifyDNRequest,
  ModifyDNResponse,
  CompareRequest,
  CompareResponse,
  AbandonRequest,
  ExtendedRequest,
  ExtendedResponse,

  // Authentications
  SimpleAuth = 0x80,
  SASL,

  // Filters
  And = 0xA0,
  Or,
  Not,
  EqualityMatch,
  Substrings,
  GreaterOrEqual,
  LessOrEqual,
  Present,
  ApproxMatch,
  ExtensibleMatch,
};

typedef struct action {
  char *name;
  uint8_t id;
  char *(*parse_func)(element_t *, char *);
} action_t;

typedef struct element {
  uint8_t id;
  uint8_t size_byte;
  uint8_t *value;
  struct element *el;
} element_t;

void element_print(const element_t *el) {
  printf("\nEL \t| id: %02x \t| size: %02x", el->id, el->size_byte);
}

char *parse_element(element_t *el, const char *offset) {
  el->id = (uint8_t)*offset;
  el->size_byte = (uint8_t)*offset + 1;
  return el->size_byte + offset;
}

element_t *parser_BindResponse(char *element_msg) {}

int main() {
  char *received_msg = BIND_RESPONSE;
  // puts("\n");
  // for (uint8_t i = 0; i < 14; i++) {
  //   printf("%02x ", received_msg[i]);
  // }

  puts("\n\nMalloc");

  char *offset = received_msg;
  element_t *head = 0;
  element_t *tail = 0;
  element_t *prev = 0;

  for (uint8_t i = 0; i < 14; i++) {
    tail = malloc(sizeof(element_t));
    if (i == 0) {
      head = tail;
      prev = tail;
    }
    prev->el = tail;

    offset = parse_element(tail, offset);

    printf("%02x ", received_msg[i]);
  }
  tail->el = 0;

  puts("\n\nFree");

  element_t *current = head;

  while (current) {
    prev = current;
    element_print(current);
    current = current->el;
    free(prev);
  }

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
