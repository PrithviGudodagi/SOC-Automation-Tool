import re

def sanitize_iocs(iocs):
    sanitized_iocs = []
    for ioc in iocs:
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ioc):
            # Masking IP addresses
            masked_ip = ioc.replace(".", "[dot]")
            sanitized_iocs.append(masked_ip)
        elif re.match(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$", ioc):
            # Masking Domains
            masked_domain = ioc.replace(".", "[dot]")
            sanitized_iocs.append(masked_domain)
        elif re.match(r"^[a-fA-F0-9]{32}$", ioc):
            # Masking MD5 Hashes
            masked_hash = f"{ioc[:8]}*****{ioc[24:]}"
            sanitized_iocs.append(masked_hash)
        else:
            sanitized_iocs.append(ioc)
    return sanitized_iocs

iocs = input("Enter the list of IOCs separated by comma: ").split(", ")
print(sanitize_iocs(iocs))