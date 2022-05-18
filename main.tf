# Cloud Armor Security policies
# Cloud Armor Security Policy, backend targets can only be mapped once to targets.
# The below Security Policy "ofac" first rule is the ofac geo-blocking rule. The rules after ofac 
# geo-blocking, are the ten OWASP rules. 
resource "google_compute_security_policy" "ofac" {
  name        = "ofac"
  description = "ofac security policy OWASP preconfigured exressions rules"
}
resource "ofac" {
  location = "us-east4"
  project = "sym-tst-xchg"
  name = "ofac"
}
rule {
  action    = "deny(403)"
  priority  = "0"
  match {
    expr {
      expression": "'[CN,KP,LT,UA,AF,DZ,EG,GN,IR,IQ,LR,LY,NE,YE,UZ,TZ,TT,VN,RO,PK,NG,AL,BA,BG,KO,ME,MK,SL,BY,MM,BI,CF,CU,CD,NI,SD,SS,SO,SY,UA,VE,ZW]'.contains(origin.region_code)"
    }
  }
  description = "Deny access to geo-block ofac countries"
}
rule {
  action   = "deny(403)"
  priority = "9000"
  match {
    expr {
      expression": "evaluatePreconfiguredExpr('sqli-stable')"
    }
  },
    description = "OWASP Deny access to SQLI attempts"
  }

rule {
  action   = "deny(403)"
  priority = "9001"
  match {
    expr {
      expression": "evaluatePreconfiguredExpr('xss-stable')"
    }
  }
    description = "OWASP Deny access to XSS attempts"
  }
 
rule {
  action   = "deny(403)"
  priority = "9002"
  match {
    expr {
      expression": "evaluatePreconfiguredExpr('lfi-stable')"
    }
  }
    description = "OWASP Deny access to LFI attempts"
  }
 
rule {
  action   = "deny(403)"
  priority = "9003"
  match {
    expr {
      expression": "evaluatePreconfiguredExpr('rfi-stable')"
    }
  }
    description = "OWASP Deny access to RFI attempts"
  }
 
 rule {
  action   = "deny(403)"
  priority = "9004"
  match {
    expr {
      expression": "evaluatePreconfiguredExpr('rce-stable')"
    }
  }
    description = "OWASP Deny access to RCE attempts"
  }
 
rule {
  action   = "deny(403)"
  priority = "9005"
  match {
    expr {
      expression": "evaluatePreconfiguredExpr('methodenforcement-stable')"
    }
  }
    description = "OWASP Method Enforcement Get,POST,Put, Delete"
  }
  rule {
  action   = "deny(403)"
  priority = "9006"
  match {
    expr {
      expression": "evaluatePreconfiguredExpr('scannerdetection-stable')"
    }
  }
    description = "OWASP Block Scanners"
  }

  rule {
  action   = "deny(403)"
  priority = "9007"
  match {
    expr {
      expression": "evaluatePreconfiguredExpr('protocolattack-stable')"
    }
  },
    description = "OWASP Block protocol attacks"
  }
  rule {
  action   = "deny(403)"
  priority = "9008"
  match {
    expr {
      expression": "evaluatePreconfiguredExpr('php-stable')"
    }
  },
    description = "OWASP Deny access to PHP attempts"
  }
  rule {
  action   = "deny(403)"
  priority = "9009"
  match {
    expr {
      expression": "evaluatePreconfiguredExpr('sessionfixation-stable')"
    }
  },
    description = "OWASP Block Session hijacking "
  }
  rule {
  action   = "deny(403)"
  priority = "9010"
  match {
    expr {
      expression": "evaluatePreconfiguredExpr('cve-canary')"
    }
  },
    description = "CVE-2021-44228 and CVE-2021-45046"
  }
  rule {
        action   = "allow"
        priority = "2147483647"
        description = "default rule"
    }
}
