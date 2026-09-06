// English. The reference catalogue: test/i18n.test.js requires every other
// locale in this directory to carry exactly these keys, with exactly these
// placeholders.
//
// Nothing here contains markup. Templates escape everything, so a translation
// cannot open a tag — and where a sentence genuinely needs emphasis, the
// template splits it into two keys rather than trusting a `<strong>`.

export default {
  code: 'en',
  endonym: 'English',

  common: {
    brand: 'Opsidious',
    homeAria: 'Opsidious, home',
    source: 'Source code',
    langAria: 'Read this page in {lang}'
  },

  layout: {
    skip: 'Skip to the main content'
  },

  home: {
    // The layout appends ' — Opsidious' to anything that is not already the
    // bare brand, so this says what the service IS. It was 'Opsidious', which
    // in a tab strip and a search result is a word with no claim in it.
    title: 'Anonymous sign-in for any application',
    eyebrow: 'Identity service',
    h1: 'An identity that does not follow you.',
    lede: 'You sign in with Google. This service is never told your email or your name — only an opaque identifier, which it does not keep either.',

    chainTitle: 'Who sees what',
    chainNote:
      'Each part says what it sees and what it cannot. The second half is the one that matters: it is what separates this from an ordinary Google sign-in. “Anonymous” is worth nothing on its own — every service says it. This can be checked.',
    sees: 'Sees',
    blind: 'Cannot see',
    parties: {
      google: {
        who: 'Google',
        sees: 'That you signed in to Opsidious.',
        blind: 'Which application you were going to.'
      },
      opsidious: {
        who: 'Opsidious',
        sees: 'An opaque Google identifier.',
        blind: 'Your email or your name — never received.'
      },
      application: {
        who: 'The application',
        sees: 'An identifier that only means anything to it.',
        blind: 'Anything that would find you somewhere else.'
      }
    },

    splitTitle: 'One person, a different identifier in every application',
    splitBody:
      'The identifier an application receives is derived from your account and from that application, and recomputed every time you sign in rather than stored. Two applications comparing their databases row by row find no value in common — not an encrypted one, not a hashed one. There is nothing shared to find.',
    splitDiaTitle: 'One account, three unrelated identifiers',
    splitDiaDesc:
      'One account enters a derivation step and three unrelated opaque identifiers come out, one per application.',
    splitDiaSource: 'YOUR ACCOUNT',
    splitDiaCut: 'DERIVED PER APPLICATION',
    // Drawn as SVG text inside a 300-unit box. SVG text neither wraps nor
    // truncates, so anything past roughly 35 characters runs out of the box
    // and over the brace beside it. Keep it to two or three words.
    splitDiaApp: 'Application {n}',
    splitDiaClaim: 'nothing in common',

    verifyTitle: 'Check rather than believe',
    verifyBody:
      'Your account page shows the six fields recorded about you, what each one is, and which of them actually tells a reader of this database anything.',
    verifyCta: 'See my account',
    verifyNote:
      'You need to be signed in from an Opsidious application for that page to have anything to show.',

    devTitle: 'For developers',
    devLede:
      'Any application may use this service. There is nobody to ask, no form to fill in, and nothing to disclose.',
    openTitle: 'Registration is open',
    openBody:
      'An application posts a name and a redirect URI and gets credentials back. No operator in the loop, no email, no account, no approval. That is not a relaxation of the design — it is what the design always implied: an application that registers learns one thing about a person who signs in, and that one thing is meaningless in every other application, including the others the same author might register.',
    openCurl: 'Register an application:',
    openReturns:
      'The secret is returned once, in that response, and never again. A public client — desktop, mobile, single-page — sends {method} instead and proves itself with PKCE.',
    // ── Ce que ce service ne défend pas ────────────────────────────────
    // Sans balisage, comme tout ce catalogue : les gabarits échappent, donc une
    // traduction ne peut jamais ouvrir une balise. L'emphase du site plateforme
    // (« structurellement absente ») disparaît donc ici, et la phrase tient
    // sans elle.
    limitsTitle: 'What this does not defend',
    limitsLede:
      'A security document that claims more than it delivers is worse than one that claims less. These are stated as plainly as the guarantees above, and at more length in the design document.',
    limits: {
      keyH: 'A dump of the database forges tokens.',
      keyP:
        'The signing key has to be reachable by the process that signs, so whoever holds the file can mint a token with any subject and any audience, and every registered application will accept it. That is true of every identity provider. It is written down anyway, with the key-rotation procedure next to it.',
      pairH: 'Holding two databases at once breaks the pairwise property.',
      pairP:
        'The identifier is a deterministic function — it has to be, or signing back in would not return you to your own account. Someone with both this database and an application’s can recompute it and prove the two share users. Nothing in this design stops that, and nothing could.',
      openH: 'Open registration is open to bad applications too.',
      openP:
        'Anyone can register, so a hostile application can too — and it gets exactly what an honest one gets: a subject that is useless anywhere else. What it does not get is a way to reach you, a way to find you in another application, or any standing with this service. The sign-in screen never displays a name an application chose, precisely so it cannot be used to impersonate one.',
      operatorH: 'The operator is not defended against.',
      operatorP:
        'Whoever runs the service can deploy a build that records whatever it likes, and no code can defend against whoever supplies it. What the design does instead is make the correlating data structurally absent: there is no column for it, so collecting it takes a deliberate, visible, auditable change rather than reading a table that was already there.'
    },

    discoveryTitle: 'Discovery',
    docsLink: 'Design document',

    // Travels alone, on a card in somebody else's timeline.
    shareDescription:
      'Sign in with Google. This service is never told your email or your name, and every application gets a different identifier for the same person.',
    shareImageAlt:
      'Opsidious Auth — an identity that does not follow you.',

    footerNote:
      'Built and run by one person. The source is public, so the claims above can be read rather than believed.'
  },

  intro: {
    title: 'Sign in',
    h1: 'Anonymous sign-in',
    sub: 'Opsidious sits between Google and the application.',
    button: 'Continue with Google',
    note: 'Once only. Your next sign-ins will be immediate.',
    footAccount: 'What is recorded about me'
  },

  account: {
    title: 'Opsidious account',
    h1: 'What we know about you',
    lede: 'Six fields. Here they are exactly as they are recorded, without rewording. Only one of them tells a reader anything — it is marked.',
    rowTitle: 'Your row',
    revealsNothing: 'Tells a reader of this database nothing about you.',

    fields: {
      id: {
        shape: 'random UUID, 122 bits',
        kind: 'Internal identifier. No application ever receives it.'
      },
      googleSubHash: {
        shape: 'HMAC-SHA256, 32 bytes',
        kind: 'Your Google identifier, put through an HMAC under a key specific to this server. The identifier itself is written nowhere.'
      },
      kdfSalt: {
        shape: '16 random bytes',
        kind: 'Used to derive the key that seals the next field.'
      },
      sealedSalt: {
        shape: '60 bytes — 12 (IV) + 16 (auth) + 32 (salt)',
        kind: 'Your pairwise salt, sealed under a key this server never keeps. It only opens at the moment you sign in.'
      },
      createdAt: {
        kind: 'The day you first signed in, rounded to the day — the time is not kept.',
        reveals: 'The day you arrived. It is the only thing this row tells a reader.'
      },
      ssoSessions: {
        kind: 'Browsers currently signed in. Each keeps only a fingerprint of its cookie, never the cookie.',
        reveals: {
          other: 'That you are signed in from {count} browsers.'
        }
      }
    },

    absentTitle: 'What exists nowhere',
    absent: {
      email: 'Your email address — we do not ask Google for it.',
      name: 'Your name — same.',
      googleSub: 'Your Google identifier in the clear — only its fingerprint is kept.',
      salt: 'Your pairwise salt in the clear — it is sealed under a key we do not keep.'
    },
    cannotLead: 'We cannot tell you which applications you use.',
    cannotBody:
      'Each one knows you under a different identifier, computed on the fly and never recorded. No table here links your account to an application. This page is not hiding that list from you: it does not exist.',

    actsTitle: 'Act',
    logoutTitle: 'Sign out',
    logoutBody: 'Closes this browser. Your account and your other sessions are untouched.',
    logoutButton: 'Sign out',
    deleteTitle: 'Delete this account',
    deleteBody:
      'Erases the row above and all your sessions, permanently. You will no longer be able to sign in to any Opsidious application.',
    deleteWarn:
      'The data held by those applications will not be erased. We would be unable to tell them which account to delete — that is the price of the anonymity described above. Delete your account in each application first.',
    deleteConfirmLabel: 'Type {word} to confirm',
    deleteButton: 'Delete permanently',
    // The word typed into the confirmation field. Every locale's word is
    // accepted, whichever language the page was rendered in — see
    // routes/account.js for why that is safe.
    deleteWord: 'DELETE'
  },

  errors: {
    title: 'Error',
    notFound: 'Page not found.',
    serverError: 'Service error.',
    clientNotAllowed: 'This application is not allowed to use Opsidious.',
    requestExpired: 'This sign-in request has expired. Start again.',
    notSignedIn: 'You are not signed in to Opsidious.',
    invalidRequest: 'Invalid request.',
    confirmDelete: 'Type {word} to confirm.'
  }
};
