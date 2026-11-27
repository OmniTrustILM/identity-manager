# Certificates and the overview

Identity Manager looks at the certificates on the computer and compares them with your ILM. This guide says what it
counts, when a certificate needs attention and what the person can do about it.

## What the overview counts

The overview counts the certificates of this computer that have a private key. A certificate without a private key is
not counted. For each one Identity Manager also knows its status in ILM: not in ILM, in ILM, or managed by ILM.

Four tiles show the counts:

| Tile          | Certificates                                                                 |
|---------------|------------------------------------------------------------------------------|
| Valid         | Valid for longer than the warning time.                                      |
| Expiring soon | Valid, but expire within the warning time.                                   |
| Expired       | Already expired.                                                             |
| Not in ILM    | Not known to ILM. Such a certificate also counts in one of the tiles above.  |

The warning time is 30 days. The person can change it in Settings ("Warn before expiry": 7, 14, 30, 60 or 90 days),
and your organization can set it with the `ExpiryWarningDays` policy key, see [policy.md](policy.md).

## When a certificate needs attention

A certificate needs attention when:

- it expires within the warning time,
- it expired recently, or
- ILM shows it as revoked.

A certificate that is not in ILM does not need attention for that reason alone.

## The chart

The chart shows, for the next 12 months, how many certificates expire in each month. Use it to see a busy month
early.

## The tray

The tray (or menu bar) icon opens a short summary with the same counts and the certificates that need attention.
Choosing one opens the main window at that certificate. While any certificate needs attention, the icon changes to
show it, except while Identity Manager is locked. While it is locked, the summary shows no counts.

## Keeping the list current

The list updates by itself while the window is open, for example after a smart card is inserted or removed. It also
updates when you return to the window.

## The card of a smart-card certificate

For a certificate whose private key is on a smart card, the details show the name of the card ("Smart card ·
YubiKey 5 NFC", for example). Without a name they show "Smart card".

- On macOS the name is the reader or card name that the system reports for the card.
- On Windows the name is the smart-card reader name of the key's container.

Identity Manager reads the name without asking for the PIN. If the card would ask for it, no name is shown.

In the list the card name replaces "Smart card" only when the certificates sit on more than one card. With one card,
or several cards of the same name, the list says "Smart card".

## Notifications

Identity Manager shows a notification when a certificate:

- expires soon,
- has expired, or
- is revoked in ILM.

Each certificate is notified once for each of these, also after a restart. On the first run at most three
notifications are shown, and one more says how many others need attention. Nothing is shown while Identity Manager is
locked. A certificate that is not in ILM never causes a notification.

## Add to ILM

The person can add a certificate that is not in ILM from its details.

- Only the certificate is sent. The chain and the private key stay on the computer.
- The person becomes the owner of the certificate in ILM.
- The person can choose a group and an RA Profile when ILM lets them list these.
- With an RA Profile, ILM manages the certificate and can renew it. Without one, ILM only tracks it.
- The person can fill in the custom attributes ILM defines for certificates when ILM lets them list these. The
  attributes are grouped as in ILM, with ungrouped ones first under "Custom attributes". Defaults are filled in,
  required values are marked, and values the administrator made read-only are shown with a lock and sent as defined.
  The values apply to every certificate in that add.
- Identity Manager checks the values as ILM does before anything is sent. A value with a problem says what is wrong,
  and the certificates cannot be added until it is corrected.
- An attribute Identity Manager cannot show is left out when it is optional. When it is required, the dialog says
  so and the certificates cannot be added from Identity Manager. "Open in ILM" opens the Certificates page of ILM's
  web interface in the browser, where the certificate can be imported with every attribute.
- ILM may refuse. Common reasons are a missing permission or an RA Profile whose authority cannot identify the
  certificate. Identity Manager shows the reason.
- A certificate that is already in ILM counts as added.

## Request a certificate

The person can request a new certificate from ILM. "Request certificate" in the toolbar of Certificates appears when
the person is signed in, Identity Manager is online, ILM allows the person to create certificates, this computer has
a key storage and ILM lists at least one RA Profile for them.

The steps are:

1. **Profile.** The person chooses an RA Profile. With only one, this step is skipped.
2. **Attributes.** The attributes ILM asks for are shown in three groups: "Certificate request", "From the RA
   profile" and "Custom attributes". Defaults are filled in and required values are marked. An optional attribute
   that Identity Manager cannot write into a request is not shown. When it is required, the step says so and the
   request cannot be made from Identity Manager. "Open in ILM" opens ILM's web interface in the browser.
3. **Private key.** The person chooses where the key is created and its type.
4. **Review.** The profile, the subject, the key and where the certificate will be installed are shown. Nothing is
   created before "Request certificate" is chosen.

### Where the private key lives

| Computer | Storage                                                                                                                                  |
|----------|------------------------------------------------------------------------------------------------------------------------------------------|
| macOS    | Your login keychain. The key cannot be exported.                                                                                         |
| Windows  | The TPM through the Microsoft Platform Crypto Provider, where the PC has one. It cannot be copied. It is tested only in CI, without a TPM. |
| Windows  | The Windows key store: a software key in your user profile. The key cannot be exported.                                                  |
| Linux    | None. There is no key storage on Linux, so "Request certificate" is not shown there.                                                     |

The key type list shows the types the chosen storage supports. EC P-256 is preselected when it is offered.

Your organization can limit the storages and set the recommended one, which is preselected and marked
"Recommended", with the `KeyStorages` and `DefaultKeyStorage` policy keys, see [policy.md](policy.md). When the policy
leaves no storage, the step says so and the person cannot continue.

### After the request

The key is created on the computer and never leaves it. Only a request signed with the key goes to ILM.

- If ILM issues the certificate at once, Identity Manager installs it and says so.
- If it waits for approval or for issuing, the window can be closed. Overview lists the request under "Requests in
  progress" with its state, "Waiting for approval" or "Being issued". Identity Manager installs the certificate at a
  later check, once ILM has issued it, and shows a notification, "Your certificate is installed", unless the window
  still showed the request.
- The certificate is installed in your login keychain on macOS and in your personal certificate store on Windows,
  together with its intermediate certificates. A root certificate is never installed and no trust setting is changed:
  your organization deploys its roots.
- If ILM rejects the request or cannot issue the certificate, a notification says so ("Request rejected" or "Request
  failed", with the name of the certificate) unless the window still showed the request, and the key is deleted.
- If ILM issued a certificate that does not match the key, it is not installed.
- ILM may refuse the request, for example for a missing permission or a value it does not accept. Identity Manager
  shows ILM's text as it is, and the person can go back and correct the attributes.

## Requests

The Requests section appears on macOS and Windows when there is something in it: requests waiting for the person's
approval, certificates prepared for the person in advance, certificates your organization asks the person to request, or the person's own requests that ILM has not finished.

### Waiting for your approval

When an RA Profile asks for approval, ILM names who approves each step: a person, a role or a group. Identity Manager
reads at every check of ILM the certificate requests waiting for the signed-in person's decision, and lists them with
the certificate's name, who asked, the RA Profile, the kind of request (a new certificate, a renewal, a rekey or a
revocation) and when it was asked. When the person may not read the certificate in ILM, the row says "Certificate". A
notification, "An approval is waiting for you", is shown once for each of them. The person's own requests are not
listed: ILM does not let anyone approve their own request.

"Approve" sends the decision at once. "Reject…" asks first and takes an optional comment, which ILM keeps with the
approval. A rejected request ends. An approved one goes to the next approver or, after the last one, ILM carries it
out. When someone else decided first or the approval expired, Identity Manager says "This request no longer waits for
your decision." and removes it from the list.

### Ready for you to issue

An administrator can register a certificate in ILM in advance, with its subject already set, and make the person its
owner. Identity Manager finds these certificates at every check of ILM and lists them under "Ready for you to issue"
with their RA Profile and, when ILM limits the time to issue them, how many days are left. A notification, "A
certificate is ready for you to issue", is shown once for each of them.

"Issue…" opens the same steps as a request, without the profile step. The subject the administrator registered is
shown and cannot be changed; the person fills in the other attributes ILM asks for and chooses where the key lives.
When ILM protects the certificate with a challenge, the Review step asks for it. The administrator gives the
challenge to the person with the certificate. Identity Manager sends it with the request and never keeps it. If ILM
does not accept it, ILM's text is shown and the person can try again; after too many wrong attempts ILM locks the
certificate.

When the time to issue has ended or the certificate is locked, the row says so and "Ask your administrator": it
cannot be issued from Identity Manager any more.

After "Issue certificate", the certificate is installed as after a request (see "After the request").

### My requests

The person's requests that are waiting for approval or being issued are listed with their state and when they were
requested. A request that ends is no longer listed; its outcome was shown or notified. A request waiting for approval
cannot be cancelled from Identity Manager, as ILM cannot cancel it.

## Enrolment by policy

Your organization can have certificates made without the person asking, with the `CompletePrepared`,
`RequestProfiles` and `SignInCertificateProfile` policy keys, see [policy.md](policy.md). It starts at the first check
of ILM after the person signs in, while Identity Manager is not locked. Nothing is enrolled on Linux.

- **Prepared certificates.** With `CompletePrepared`, every open certificate that an administrator prepared for the
  person (see "Ready for you to issue") is completed by itself and installed, as after "Issue certificate". The
  subject the administrator registered is used.
- **Requested profiles.** Each RA Profile named in `RequestProfiles` is requested once for each person and computer,
  with the key in the storage the policy chooses (`DefaultKeyStorage`, `KeyStorages`). Afterwards renewal keeps the
  certificate current. If the certificate is revoked or deleted later, it is not requested again. A name that ILM does
  not list for the person is skipped.
- **A failed attempt** is tried again at the next check, at most once a day.

The challenge always stays with the person. A prepared certificate whose registration asks for a challenge is not
completed by itself and stays under "Ready for you to issue".

A form that needs the person, for example a value to choose or a required value that has no default, is not sent. It
shows in Requests under "Asked by your organization" with the name of the RA Profile and "Request…", which opens the
request at its attributes. One notification, "Your organization asks you to request a certificate: <profile>", tells
the person. When the request is sent, the row goes away.

ILM decides what is allowed. A requested profile needs the permission `certificates:create` for the person; without
it nothing is requested. Completing a prepared certificate is tried without that check and ILM decides, as it does for
"Issue…". When a request fails, the notification says "Request failed: <name>", and adds "ILM does not allow this."
when ILM refuses the person's right to request.

A notification is shown once, when:

- an enrolled certificate is installed ("Your certificate is ready: <name>"),
- the organization asks for a request that needs the person (see above), or
- an enrolment failed ("Request failed: …").

An enrolment that works is otherwise quiet. A prepared certificate that is completed by itself causes no "A
certificate is ready for you to issue" notification.

## Automatic renewal

Identity Manager renews the certificates of this computer that ILM manages, before they expire. It does so while you
are signed in and Identity Manager is not locked. Nothing is renewed on Linux.

### When it renews

A certificate is renewed when ILM's renewal window for the RA Profile has opened. When the RA Profile has no window,
it is renewed when it expires within the warning time (see "What the overview counts"), or within half its validity
when that is shorter. The check runs with every check of ILM. A certificate is not renewed again while ILM has a
renewal of it waiting or issued. When a renewal fails, the next attempt for that certificate waits at least a day.

A certificate is renewed only when ILM allows you to renew it. ILM needs the permissions `certificates:renew` and
`certificates:create` for you, and `certificates:revoke` to revoke a certificate. Without the permission to renew,
the certificate shows no renewal controls, is not renewed, and one notification says so.

### New key or same key

By default each renewal makes a new private key, in the same kind of storage as the old key: the login keychain, the
Windows key store or the TPM, as your organization's policy allows. The key type is the old one when the storage
offers it. The new certificate is installed beside the old one.

Renewal with the same key is used when you choose it, and automatically when a new key cannot be made where the old
one is, for example on a smart card. The key is then not touched. On macOS a smart-card certificate cannot be renewed
by Identity Manager itself, and a notification says so.

### The settings

- **Settings, General, "Automatic renewal":** Off, New key or Same key. Your organization can fix it with the
  `AutomaticRenewal` policy key, see [policy.md](policy.md); the row is then locked. With Off from policy, no
  certificate is renewed automatically.
- **"Renew automatically"** in the Renewal group of a certificate's details. It is kept on this computer, belongs to
  that certificate and is carried to the renewed certificate. The details also show when the renewal happens and
  whether it uses a new key or the same key.
- **"Renew now"** renews the certificate at once, whatever the switch says. ILM must still allow it.

### After a renewal

- A renewal that needs approval shows in Overview, under "Requests in progress", as "Renewal waiting for approval".
  Identity Manager installs the certificate once ILM has issued it.
- When the old certificate was your sign-in certificate, the sign-in moves to the renewed one.
- The old certificate stays on the computer until it expires. It is shown as "Replaced", needs no attention and
  causes no expiry notification.

### Notifications

A renewal that works is quiet. A notification is shown, once for each case, when:

- a renewal failed ("Renewal failed", with ILM's reason),
- a certificate is due while you are signed out or Identity Manager is locked ("Sign in to renew"), or
- a certificate cannot renew itself, with the reason: ILM does not allow it, it is a smart-card certificate on macOS,
  or the sign-in could not move to the renewed certificate.

## Revoke

"Revoke…" in a certificate's details asks ILM to revoke the certificate. It is shown only when ILM allows you to
revoke it, which needs the permission `certificates:revoke`. Nothing is revoked on Linux.

- **Reason:** No longer needed (the default), Replaced, Key compromised, Affiliation changed, Privilege withdrawn or
  Unspecified. ILM records it with the revocation.
- **"Delete it and its private key from this Mac"** ("this PC" on Windows) removes the certificate and deletes its key
  once ILM has revoked it. It is offered for a key in the login keychain, the Windows key store or the TPM. The key is
  kept while another certificate on this computer, or a renewal of it in ILM, may use it, and on Windows when an older
  cryptographic provider holds it; the certificate is removed all the same.
- **"Remove it from this PC"** is offered for a smart-card certificate on Windows instead: the certificate is removed,
  and the key stays on the card. On macOS a smart-card certificate is on the card only, so nothing is offered.

Revoking cannot be undone. The certificate stops working everywhere within minutes. With an approval profile in ILM,
the revocation waits for approval first, and the details say "Revocation waiting for approval" until it is decided.
While a revocation waits, the certificate is not renewed, automatically or with Renew now.
Nothing leaves the computer before ILM says the certificate is revoked; without the option ticked, the certificate
stays and is listed as revoked.

A revocation you made here causes no "revoked" notification. When ILM does not revoke the certificate, a notification
"Revocation failed" says so, unless the details still show it.
