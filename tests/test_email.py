from pathfinder import emailmsg

_RAW = b"""From: "Microsoft Security" <alerts@secure-microsft-verify.tk>
Reply-To: harvest@evil.ru
Return-Path: <bounce@secure-microsft-verify.tk>
Subject: Action required: verify your account
Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=secure-microsft-verify.tk; dkim=fail header.d=secure-microsft-verify.tk; dmarc=fail
Received: from mail.evil.ru (mail.evil.ru [45.146.165.37]) by mx.google.com with ESMTPS
Content-Type: text/plain

Please verify your account at http://secure-microsft-verify.tk/login right now.
"""


def test_email_parse_signals():
    e = emailmsg.parse(_RAW)
    assert e["from_domain"] == "secure-microsft-verify.tk"
    assert e["spf"] == "fail" and e["dkim"] == "fail" and e["dmarc"] == "fail"
    assert e["display_name_spoof"] is True          # "Microsoft" in display name
    assert e["reply_to_mismatch"] is True           # evil.ru != sender domain
    assert "http://secure-microsft-verify.tk/login" in e["urls"]
    assert "45.146.165.37" in e["received_ips"]


def test_email_attachment_hash():
    raw = (b"From: a@b.com\nSubject: x\n"
           b"Content-Type: multipart/mixed; boundary=BND\n\n"
           b"--BND\nContent-Type: text/plain\n\nhi\n"
           b"--BND\nContent-Type: application/octet-stream\n"
           b"Content-Disposition: attachment; filename=\"invoice.exe\"\n"
           b"Content-Transfer-Encoding: base64\n\naGVsbG8=\n--BND--\n")
    e = emailmsg.parse(raw)
    assert e["attachments"] and e["attachments"][0]["filename"] == "invoice.exe"
    # sha256 of b"hello"
    assert e["attachments"][0]["sha256"] == \
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
