local sso_auth = { }

local function init()
  local handle, msg, err = io.open("/dev/urandom", "r")
  if handle then
    ngx.shared.sso:set("secret", ngx.encode_base64(ngx.sha1_bin(handle:read(32))))
    handle:close()
  else
    ngx.log(ngx.ERR, "Cannot access \"/dev/urandom\"; SSO authentication will not work")
  end
end

function sso_auth.GetRespCookies()
  local cookies = ngx.header["Set-Cookie"]
  if cookies then
    if type(cookies) ~= "table" then
      cookies = { cookies }
      ngx.header["Set-Cookie"] = cookies
    end
  else
    cookies = { }
  end
  return cookies
end

function sso_auth.GetRespCookie(cookie)
  local cookies = sso_auth.GetRespCookies()
  local key = cookie:gsub("=.*", "")
  for i, val in ipairs(cookies) do
    if key == val:gsub("=.*", "") then
      return val, i, cookies
    end
  end
  return nil, #cookies + 1, cookies
end

function sso_auth.SetCookie(cookie, delay)
  if delay then
    local cookies = ngx.ctx.sso_set_cookie
    if not cookies then
      cookies = { }
    end
    cookies[cookie:gsub("=.*", "")] = cookie:gsub("^[^=]*=", "")
    ngx.ctx.sso_set_cookie = cookies
  else
    local val, i, cookies = sso_auth.GetRespCookie(cookie)
    cookies[i] = cookie
    ngx.header["Set-Cookie"] = cookies
  end
end

function sso_auth.ExpireCookie(cookie, delay)
  sso_auth.SetCookie(cookie:gsub("=.*", "") ..
                     "=; path=/; expires=Thu, 1 Jan 1970 00:00:00 UTC",
                     delay)
end

local function FlattenRespCookies()
  local delayed = ngx.ctx.sso_set_cookie
  if not delayed then
    return
  end
  local cookies = sso_auth.GetRespCookies()
  for i, val in ipairs(cookies) do
    local k = val:gsub("=.*", "")
    if not delayed[k] then
      delayed[k] = val:gsub("^[^=]*=", "")
    end
  end
  cookies = { }
  for k, v in pairs(delayed) do
    cookies[#cookies + 1] = k .. "=" .. v
  end
  ngx.header["Set-Cookie"] = cookies
  ngx.ctx.sso_set_cookie = nil
end

function sso_auth.challenge()
  -- Retrieve global "secret" to be used for signing
  local key = ngx.shared.sso:get("secret")
  if not key or key == "" then
    ngx.log(ngx.ERR, "sso:secret was not initialized by init-auth.conf")
    return ngx.exit(ngx.ERROR)
  end
  
  -- Obtain the current time, sign it, and use it as a challenge for the login
  -- web page.
  -- First, convert current time to binary representation.
  local tm = math.abs(ngx.time())
  local raw = ""
  for i = 1, 4 do
    raw = raw .. string.char(tm % 256)
    tm = tm / 256
  end
  
  -- Then encode current time and HMAC-SHA1 signature as a single Base64 encoded
  -- string.
  -- This results in a string that is exactly 35 characters long (including
  -- surrounding quotes and semicolon).
  tm = "\"" .. ngx.encode_base64(raw .. ngx.hmac_sha1(key, raw)) .. "\";"
  if tm:len() ~= 35 then return ngx.exit(ngx.ERROR) end
  
  -- Insert the parameter into the HTML source. Try to keep the existing length
  -- of the file, so that we don't need to worry about recomputing Content-Length.
  ngx.arg[1] = ngx.arg[1]:
    gsub("(challenge%s*=%s*)\"" .. string.rep("%d", 32) .. "\";", "%1" .. tm, 1)
end

function sso_auth.csrfProtection(url)
  local ref = ngx.req.get_headers()["Referer"];
  if ref and not ref:match("^" .. url) then
    ngx.header["Content-Type"] = "text/html"
    ngx.header["Refresh"] = "0;URL=" .. url
    return ngx.exit(200)
  end
end

function sso_auth.access()
  local SESSION_TIMEOUT = 60*60
  local LOGIN_TIMEOUT   = 15*60
  
  -- Retrieve global "secret" to be used for signing
  local key = ngx.shared.sso:get("secret")
  if not key or key == "" then
    ngx.log(ngx.ERR, "sso:secret was not initialized by init-auth.conf")
    return ngx.exit(ngx.ERROR)
  end
  
  -- The caller also provides the realm that should be protected by the
  -- SSO authentication.
  local realm = ngx.var.sso_realm;
  if not realm or realm == "" then
    ngx.log(ngx.ERR, "Caller did not set $sso_realm")
    return ngx.exit(ngx.ERROR)
  end
  
  -- Convert time to four raw bytes
  function TimeToRaw(tm)
    tm = math.abs(tm)
    local raw = ""
    for i = 1, 4 do
      raw = raw .. string.char(tm % 256)
      tm = tm / 256
    end
    return raw
  end
  
  -- Convert four raw bytes to time
  function RawToTime(raw)
    local tm0, tm1, tm2, tm3 = raw:byte(1, 4)
    return ((tm3*256 + tm2)*256 + tm1)*256 + tm0
  end
  
  -- Read matching line from "auth-sso" file
  function ReadSSO(user)
    local handle, msg, err = io.open("/etc/sso-auth", "r")
    if not handle then return end
  
    for line in handle:lines() do
      local u,h,r = line:
                    match("([^#]*).*"):
                    match("^%s*([^%s]*)%s+([^%s]*)%s+([^%s]*).*$")
      if u and h and r and u ~= "" and h ~= "" and r ~= "" then
        if u == user then
          handle:close()
          return u, h, r
        end
      end
    end
    handle:close()
    return
  end
  
  -- Retrieve cookie value as table
  function GetSSOCookie()
    local cookie = ngx.var.cookie_SSOAuth
    if cookie then
      local hmac, tm_raw, realms = ngx.decode_base64(cookie):
         match("^(" .. string.rep(".", 20) .. ")(....)(.*)$")
      if hmac and hmac ~= "" and realms and realms ~= "" and
         ngx.hmac_sha1(key, tm_raw .. realms) == hmac then
        local diff = ngx.time() - RawToTime(tm_raw)
        if diff >= 0 and diff < SESSION_TIMEOUT then
          return realms
        end
      end
    end
    return nil
  end
  
  -- Set the cookie after adding a timestamp and signature
  function SetSSOCookie(realms, force)
    if realms and realms ~= "" then
      local tm_raw = TimeToRaw(ngx.time())
      realms = tm_raw .. realms
      local cookie =
        "SSOAuth=" ..
        ngx.encode_base64(ngx.hmac_sha1(key, realms) .. realms) ..
        "; path=/" .. "; HttpOnly"
      if ngx.var.scheme == "https" then
        cookie = cookie .. "; secure"
      end
      sso_auth.SetCookie(cookie, not force)
    end
  end
  
  -- Extend the time that the user is logged into the SSO system
  function ExtendCookieDuration(realm)
    local realms = GetSSOCookie()
    if realms and realms ~= "" then
      for s in realms:gmatch("[^,]+") do
        if realm == s then
          SetSSOCookie(realms)
          return true
        end
      end
    end
    return false
  end
  
  -- If the user has a valid cookie, allow the request
  if ExtendCookieDuration(realm) then
    return
  end
  
  -- The user submitted a user id and password. Verify the provided information
  -- and then decide whether to allow the request.
  if ngx.req.get_method() == "POST" then
    repeat
      -- Read POST arguments. This includes user id, hashed password, and other
      -- data.
      ngx.req.read_body()
      local args, err = ngx.req.get_post_args()
      if not args then break end
  
      -- If this was a request for a user's "salt", handle that here.
      local user = args["sso_salt_request"]
      if user then
        local u, h, r = ReadSSO(user)
        if u == user then
          -- Return the "salt" value in a custom header.
          ngx.header["X-Salt"] = h:match("([^:]*)")
        else
          -- If the user doesn't exist, make-up a fake, but plausible "salt" value.
          ngx.header["X-Salt"] = ngx.encode_base64(ngx.hmac_sha1(key, user)):sub(1, 8)
        end
        return ngx.exit(200)
      end
  
      -- Make sure we got all the arguments that we need to make a decision
      user = args["sso_auth_user"]
      local challenge = args["sso_auth_challenge"]
      local password_hash = args["sso_auth_password_hash"]
      if not user or user == "" or
         not challenge or challenge == "" or
         not password_hash or password_hash == "" then
        break
      end
  
      -- Check signature on signed "challenge"
      local tm_raw, tm_hmac = ngx.decode_base64(challenge):match("(....)(.*)")
      if ngx.hmac_sha1(key, tm_raw) ~= tm_hmac then break end
  
      -- Compute time when challenge was issued and reconfirm the password if
      -- the password dialog has expired
      local diff = ngx.time() - RawToTime(tm_raw)
      if diff < 0 or diff >= LOGIN_TIMEOUT then
        break
      end
  
      -- Read "sso-auth" file
      local u, h, r = ReadSSO(user)
      if u == user then
        -- Check if the password matches.
        local salt, hash = h:match("([^:]*):(.*)")
        local dat1 = ngx.hmac_sha1(ngx.decode_base64(challenge), ngx.decode_base64(hash))
        local dat2 = ngx.decode_base64(password_hash)
        local data = ""
        for i = 1, #dat1 do
          data = data .. string.char((256 + dat2:byte(i) - dat1:byte(i)) % 256)
        end
        if ngx.encode_base64(ngx.sha1_bin(data)) == hash then
          -- Check if the user has access to this particular "realm"
          for s in r:gmatch("[^,]+") do
            if realm == s then
              -- The user provided a correct user id and password for this realm;
              -- allow the request; and also log the user into all of his realms.
              SetSSOCookie(r, true)
              ngx.req.set_method(ngx.HTTP_GET)
              return
            end
          end
        end
      end
    until true
  end
  
  -- The user is (still) unauthenticated. Inject a login page and ask for
  -- credentials.
  ngx.req.set_method(ngx.HTTP_GET)
  ngx.header["Content-Type"] = "text/html"
  return ngx.exec("/auth")
end

function sso_auth.headerFilter()
  FlattenRespCookies()
  if ngx.header.content_type and
    (ngx.header.content_type:find("text/html") or
     ngx.header.content_type:find("application/xhtml[+]xml")) then
    ngx.header.content_length = nil
  end
end

function sso_auth.bodyFilter()
  if ngx.arg[1]:find("<frameset") then
    return
  end
  if ngx.header.content_type and
    (ngx.header.content_type:find("text/html") or
     ngx.header.content_type:find("application/xhtml[+]xml")) then
    ngx.arg[1] = ngx.re.sub(ngx.arg[1], "</head>",
        "<style>\
          a.sso_auth_overlay {\
            background: rgba(240,240,240,0.4) none !important;\
            box-shadow: none !important;\
            color: transparent !important;\
            font-family: Arial, sans-serif !important;\
            font-size: 16px !important;\
            font-weight: normal !important;\
            height: 3px !important;\
            opacity: 1 !important;\
            overflow-y: hidden !important;\
            padding: 0px 20px !important;\
            position: fixed !important;\
            right: 0px !important;\
            text-decoration: none !important;\
            text-shadow: #fff !important;\
            top: 0px !important;\
            z-index: 30000 !important;\
          }\
          a.sso_auth_overlay:hover {\
            background: rgba(240,240,240,0.4) none !important;\
            box-shadow: none !important;\
            color: #000 !important;\
            font-family: Arial, sans-serif !important;\
            font-size: 16px !important;\
            font-weight: normal !important;\
            height: 1em !important;\
            opacity: 1 !important;\
            overflow-y: visible !important;\
            padding: 20px !important;\
            position: fixed !important;\
            right: 0px !important;\
            text-decoration: none !important;\
            text-shadow: #fff 0.1em 0.1em 0.2em !important;\
            top: 0px !important;\
            transition: height 0.15s linear, color 0.15s linear !important;\
            z-index: 30000 !important;\
          }\
        </style>\
      </head>\
      <a class=\"sso_auth_overlay\" style=\"\
        background: rgba(240,240,240,0.2) none;\
        box-shadow: none;\
        color: transparent;\
        font-family: Arial, sans-serif;\
        font-size: 16px;\
        font-weight: normal;\
        height: 3px;\
        opacity: 1;\
        overflow-y: hidden;\
        padding: 0px 20px;\
        position: fixed;\
        right: 0px;\
        text-decoration: none;\
        text-shadow: #fff;\
        top: 0px;\
        z-index: 30000;\" href=\"/logout\" target=\"_top\">Logout</a>");
  end
end

init()
return sso_auth
