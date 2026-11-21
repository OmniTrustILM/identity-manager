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
- ILM may refuse. Common reasons are a missing permission, custom attributes that ILM requires, or an RA Profile
  whose authority cannot identify the certificate. Identity Manager shows the reason.
- A certificate that is already in ILM counts as added.
