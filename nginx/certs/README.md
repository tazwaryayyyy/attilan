# Production TLS Certificates 

Store validated domain TLS payloads directly here:
- `fullchain.pem`: Canonical complete certificate assembly from Certificate Authority. 
- `privkey.pem`: Companion RSA/ECDSA keying material. 

Protocol configuration restricts negotiation strictly to TLS 1.3 `ssl_protocols TLSv1.3`. 
Files absent during stack instantiation result in critical halt directives at Edge initialization. Ensure keys remain outside standard version tracking boundaries.
