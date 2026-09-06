// Français. Mêmes clés et mêmes placeholders que en.js — test/i18n.test.js
// refuse tout écart. Écrit en français, pas décalqué de l'anglais.

export default {
  code: 'fr',
  endonym: 'Français',

  common: {
    brand: 'Opsidious',
    homeAria: 'Opsidious, accueil',
    platformAria: 'Opsidious, la plateforme dont ce service fait partie',
    source: 'Code source',
    langAria: 'Lire cette page en {lang}'
  },

  layout: {
    skip: 'Aller au contenu'
  },

  home: {
    // Le gabarit ajoute « — Opsidious » à tout titre qui n'est pas déjà la
    // marque seule : celui-ci dit donc ce QU'EST le service. C'était
    // « Opsidious », un mot sans affirmation dans un onglet ou un résultat.
    title: 'Connexion anonyme pour n’importe quelle application',
    eyebrow: 'Service d’identité',
    h1: 'Une identité qui ne vous suit pas.',
    lede: 'Vous vous connectez avec Google. Ce service ne reçoit ni votre e-mail, ni votre nom — seulement un identifiant opaque, qu’il ne conserve pas non plus.',

    chainTitle: 'Qui voit quoi',
    chainNote:
      'Chaque partie dit ce qu’elle voit et ce qu’elle ne voit pas. La seconde moitié est celle qui compte : c’est elle qui distingue ceci d’une connexion Google ordinaire. « Anonyme » ne vaut rien tout seul — tous les services l’emploient. Ceci se vérifie.',
    sees: 'Voit',
    blind: 'Ne peut pas voir',
    parties: {
      google: {
        who: 'Google',
        sees: 'Que vous vous connectez à Opsidious.',
        blind: 'Vers quelle application vous alliez.'
      },
      opsidious: {
        who: 'Opsidious',
        sees: 'Un identifiant Google opaque.',
        blind: 'Votre e-mail ou votre nom — jamais reçus.'
      },
      application: {
        who: 'L’application',
        sees: 'Un identifiant qui n’a cours que chez elle.',
        blind: 'Quoi que ce soit qui vous retrouverait ailleurs.'
      }
    },

    splitTitle: 'Une personne, un identifiant différent dans chaque application',
    splitBody:
      'L’identifiant que reçoit une application est dérivé de votre compte et de cette application, et recalculé à chaque connexion plutôt que stocké. Deux applications comparant leurs bases ligne à ligne n’y trouvent aucune valeur commune — ni chiffrée, ni hachée. Il n’y a rien de partagé à trouver.',
    splitDiaTitle: 'Un compte, trois identifiants sans rapport',
    splitDiaDesc:
      'Un compte entre dans une étape de dérivation et trois identifiants opaques sans rapport en ressortent, un par application.',
    splitDiaSource: 'VOTRE COMPTE',
    splitDiaCut: 'DÉRIVÉ PAR APPLICATION',
    // Tracé en texte SVG dans une boîte de 300 unités. Le texte SVG ne se
    // renvoie pas à la ligne et ne se tronque pas : au-delà d'environ 35
    // caractères, il sort de la boîte et passe sur l'accolade. Deux ou trois
    // mots au maximum.
    splitDiaApp: 'Application {n}',
    splitDiaClaim: 'rien en commun',

    verifyTitle: 'Vérifiez plutôt que de croire',
    verifyBody:
      'Votre page de compte affiche les six champs enregistrés sur vous, ce qu’est chacun, et lequel apprend réellement quelque chose à qui lit cette base.',
    verifyCta: 'Voir mon compte',
    verifyNote:
      'Vous devez être connecté depuis une application Opsidious pour que cette page ait quelque chose à afficher.',

    devTitle: 'Pour les développeurs',
    devLede:
      'N’importe quelle application peut utiliser ce service. Personne à qui demander, aucun formulaire, rien à déclarer.',
    openTitle: 'L’enregistrement est ouvert',
    openBody:
      'Une application publie un nom et une URI de redirection, et reçoit ses identifiants. Aucun opérateur dans la boucle, aucun e-mail, aucun compte, aucune validation. Ce n’est pas un relâchement du design : c’est ce que le design impliquait depuis le début. Une application qui s’enregistre apprend une chose d’une personne qui se connecte, et cette chose ne signifie rien dans toutes les autres applications — y compris les autres qu’enregistrerait le même auteur.',
    openCurl: 'Enregistrer une application :',
    openReturns:
      'Le secret est renvoyé une seule fois, dans cette réponse, et jamais ensuite. Un client public — bureau, mobile, page unique — envoie {method} à la place et se prouve par PKCE.',
    // ── Ce que ce service ne défend pas ────────────────────────────────
    // Sans balisage : les gabarits échappent tout, donc une traduction ne peut
    // jamais ouvrir une balise.
    limitsTitle: 'Ce que ceci ne défend pas',
    limitsLede:
      'Un document de sécurité qui promet plus qu’il ne tient vaut moins qu’un document qui promet moins. Ces points sont énoncés aussi nettement que les garanties ci-dessus, et plus longuement dans le document de conception.',
    limits: {
      keyH: 'Une copie de la base permet de forger des jetons.',
      keyP:
        'La clé de signature doit être atteignable par le processus qui signe : qui détient le fichier peut frapper un jeton portant n’importe quel sujet et n’importe quelle audience, et toutes les applications enregistrées l’accepteront. C’est vrai de tout fournisseur d’identité. C’est écrit ici quand même, avec la procédure de rotation juste à côté.',
      pairH: 'Détenir deux bases à la fois casse la propriété pairwise.',
      pairP:
        'L’identifiant est une fonction déterministe — il doit l’être, sinon vous reconnecter ne vous rendrait pas votre propre compte. Qui possède à la fois cette base et celle d’une application peut le recalculer et prouver que les deux partagent des utilisateurs. Rien dans ce design ne l’empêche, et rien ne le pourrait.',
      openH: 'Un enregistrement ouvert est ouvert aux mauvaises applications aussi.',
      openP:
        'N’importe qui peut s’enregistrer, donc une application hostile le peut aussi — et elle obtient exactement ce qu’obtient une application honnête : un sujet inutilisable ailleurs. Ce qu’elle n’obtient pas : un moyen de vous joindre, un moyen de vous retrouver dans une autre application, ou le moindre crédit auprès de ce service. L’écran de connexion n’affiche jamais un nom choisi par une application, précisément pour qu’il ne serve pas à en usurper une.',
      operatorH: 'L’exploitant n’est pas un adversaire contre lequel on se défend.',
      operatorP:
        'Qui fait tourner le service peut déployer une version qui enregistre ce qu’elle veut, et aucun code ne défend contre la source du code qui s’exécute. Ce que fait le design à la place : rendre la donnée de corrélation structurellement absente. Il n’y a pas de colonne pour elle, donc la collecter demande un changement délibéré, visible et auditable, plutôt que la lecture d’une table déjà présente.'
    },

    discoveryTitle: 'Découverte',
    docsLink: 'Document de conception',

    // Voyage seul, sur une carte dans le fil de quelqu'un d'autre.
    shareDescription:
      'Vous vous connectez avec Google. Ce service ne reçoit ni votre e-mail ni votre nom, et chaque application reçoit un identifiant différent pour la même personne.',
    shareImageAlt:
      'Opsidious Auth — une identité qui ne vous suit pas.',

    footerNote:
      'Construit et exploité par une seule personne. Le code est public : les affirmations ci-dessus se lisent au lieu de se croire.'
  },

  intro: {
    title: 'Connexion',
    h1: 'Connexion anonyme',
    sub: 'Opsidious se place entre Google et l’application.',
    button: 'Continuer avec Google',
    note: 'Une seule fois. Vos prochaines connexions seront immédiates.',
    footAccount: 'Ce qui est enregistré sur moi'
  },

  account: {
    title: 'Compte Opsidious',
    h1: 'Ce que nous savons de vous',
    lede: 'Six champs. Les voici tels qu’ils sont enregistrés, sans reformulation. Un seul apprend quelque chose à qui les lit — il est signalé.',
    rowTitle: 'Votre ligne',
    revealsNothing: 'N’apprend rien sur vous à qui lit cette base.',

    fields: {
      id: {
        shape: 'UUID aléatoire, 122 bits',
        kind: 'Identifiant interne. Aucune application ne le reçoit jamais.'
      },
      googleSubHash: {
        shape: 'HMAC-SHA256, 32 octets',
        kind: 'Votre identifiant Google, passé dans un HMAC sous une clé propre à ce serveur. L’identifiant lui-même n’est écrit nulle part.'
      },
      kdfSalt: {
        shape: '16 octets aléatoires',
        kind: 'Sert à dériver la clé qui scelle le champ suivant.'
      },
      sealedSalt: {
        shape: '60 octets — 12 (IV) + 16 (auth) + 32 (sel)',
        kind: 'Votre sel pairwise, scellé sous une clé que ce serveur ne conserve jamais. Il ne s’ouvre qu’au moment où vous vous connectez.'
      },
      createdAt: {
        kind: 'Le jour de votre première connexion, arrondi à la journée — l’heure n’est pas gardée.',
        reveals: 'Le jour où vous êtes arrivé. C’est la seule chose que cette ligne apprend à qui la lit.'
      },
      ssoSessions: {
        kind: 'Navigateurs actuellement connectés. Chacun ne garde qu’une empreinte de son cookie, jamais le cookie.',
        reveals: {
          other: 'Que vous êtes connecté depuis {count} navigateurs.'
        }
      }
    },

    absentTitle: 'Ce qui n’existe nulle part',
    absent: {
      email: 'Votre adresse e-mail — nous ne la demandons pas à Google.',
      name: 'Votre nom — même chose.',
      googleSub: 'Votre identifiant Google en clair — seule son empreinte est gardée.',
      salt: 'Votre sel pairwise en clair — il est scellé sous une clé que nous ne conservons pas.'
    },
    cannotLead: 'Nous ne pouvons pas vous dire quelles applications vous utilisez.',
    cannotBody:
      'Chacune vous connaît sous un identifiant différent, calculé à la volée et jamais enregistré. Aucune table, ici, ne relie votre compte à une application. Cette page ne vous cache pas cette liste : elle n’existe pas.',

    actsTitle: 'Agir',
    logoutTitle: 'Se déconnecter',
    logoutBody: 'Ferme ce navigateur-ci. Votre compte et vos autres sessions restent intacts.',
    logoutButton: 'Se déconnecter',
    deleteTitle: 'Supprimer ce compte',
    deleteBody:
      'Efface la ligne ci-dessus et toutes vos sessions, définitivement. Vous ne pourrez plus vous connecter à aucune application Opsidious.',
    deleteWarn:
      'Les données détenues par ces applications ne seront pas effacées. Nous serions incapables de leur dire quel compte supprimer — c’est le prix de l’anonymat décrit plus haut. Supprimez d’abord votre compte dans chaque application.',
    deleteConfirmLabel: 'Saisissez {word} pour confirmer',
    deleteButton: 'Supprimer définitivement',
    deleteWord: 'SUPPRIMER'
  },

  errors: {
    title: 'Erreur',
    notFound: 'Page introuvable.',
    serverError: 'Erreur du service.',
    clientNotAllowed: 'Cette application n’est pas autorisée à utiliser Opsidious.',
    requestExpired: 'Cette demande de connexion a expiré. Recommencez.',
    notSignedIn: 'Vous n’êtes pas connecté à Opsidious.',
    invalidRequest: 'Requête invalide.',
    confirmDelete: 'Saisissez {word} pour confirmer.'
  }
};
