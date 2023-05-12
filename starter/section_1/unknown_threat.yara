rule unknown_threat {
        meta:
                Author = "manuel wathall"
                Description = "the rule detects the presence of darklOrd script"
        strings:
                $domain = "darkl0rd.com"
        condition:
                all of them
}