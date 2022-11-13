{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DeriveGeneric #-}

module Main where

import Control.Monad.IO.Class (MonadIO (liftIO))
import qualified Crypto.Hash.SHA256 as SHA256
import Data.Aeson ((.=), FromJSON (parseJSON), ToJSON (toEncoding), genericToEncoding, defaultOptions, Options(..), genericParseJSON, decode, withObject, (.:))
import Data.Aeson.Types (object)
import Data.ByteString as B ( ByteString )
import qualified Data.ByteString.Base64 as Base64 ( encode )
import Data.ByteString.Builder (toLazyByteString, byteStringHex)
import qualified Data.ByteString.Char8 as BS (pack, unpack)
import qualified Data.ByteString.Lazy.Char8 as BL (pack)
import Data.ByteString.Lazy (toStrict)
import Data.Char (toUpper)
import Data.List (isPrefixOf, isSuffixOf, find, intercalate)
import Data.Text as T ( unpack, pack )
import Data.Text.Encoding as T ( decodeUtf8, encodeUtf8 )
import Data.Text.IO as T ()
import GHC.Generics ( Generic )
import qualified Network.HTTP.Client as L ( CookieJar )
import Network.HTTP.Req
    ( bsResponse,
      defaultHttpConfig,
      http,
      req,
      responseBody,
      responseHeader,
      responseStatusCode,
      runReq,
      GET(GET),
      NoReqBody(NoReqBody), responseCookieJar, (/:), POST (POST), ReqBodyJson (ReqBodyJson), cookieJar )
import System.Environment (getEnv)
import Text.HandsomeSoup ( (!), css, parseHtml )
import Text.XML.HXT.Core ( (>>>), runX )

byteStringToString :: ByteString -> String
byteStringToString = T.unpack . T.decodeUtf8

requiredMeta :: String -> [(String, String)] -> String
requiredMeta key meta = case lookup key meta of
  Just value -> value
  Nothing    -> error $ "Required meta tag not found: " ++ key

computeHash :: String -> String
computeHash s =
  hexStr where
    bs = BS.pack s
    hash = SHA256.hash bs
    hexStr = BS.unpack . toStrict . toLazyByteString . byteStringHex $ hash

encodeBase64 :: String -> String
encodeBase64 = BS.unpack . Base64.encode . BS.pack

data Tokens = Tokens
  { csrfToken :: !String
  , csrfParam :: !String
  } deriving (Show)

visitStartPage :: IO (Tokens, L.CookieJar)
visitStartPage = do
  (response, cookies) <- runReq defaultHttpConfig $ do
    startPageRequest <-
      req
        GET
        (http "192.168.1.1")
        NoReqBody
        bsResponse
        mempty
    let responseBody_ = byteStringToString $ responseBody startPageRequest
    let cookieJar = responseCookieJar startPageRequest
    pure (responseBody_, cookieJar)

  let htmlDoc = parseHtml response
  let metas = htmlDoc >>> css "head > meta"
  metaNames <- runX $ metas ! "name"
  metaContents <- runX $ metas ! "content"
  let metaMap = zip metaNames metaContents

  let csrfToken = requiredMeta "csrf_token" metaMap
  let csrfParam = requiredMeta "csrf_param" metaMap
  let tokens = Tokens {..}
  pure (tokens, cookies)

data Config = Config
  { userName :: !String
  , password :: !String
  , deviceName :: !String
  } deriving (Show)

loadConfig :: IO Config
loadConfig = do
  userName <- getEnv "ROUTER_ADMIN_LOGIN"
  password <- getEnv "ROUTER_ADMIN_PASSWORD"
  deviceName <- getEnv "ROUTER_TARGET_DEVICE"
  pure Config {..}

encodePassword :: Config -> Tokens -> String
encodePassword Config {..} Tokens {..} =
  computeHash $ userName ++ (encodeBase64 . computeHash $ password) ++ csrfParam ++ csrfToken

executeLogin :: Config -> Tokens -> L.CookieJar -> IO L.CookieJar
executeLogin config@Config {..} tokens@Tokens {..} cookies = do
  runReq defaultHttpConfig $ do
    let encodedPassword = encodePassword config tokens
    let payload =
            object
              [ "csrf" .= object [
                  "csrf_param" .= csrfParam,
                  "csrf_token" .= csrfToken
                ],
                "data" .= object [
                  "UserName" .= userName,
                  "Password" .= encodedPassword,
                  "isDestroyed" .= False,
                  "isDestroying" .= False,
                  "isInstance" .= True,
                  "isObserverable" .= True
                ]
              ]
    loginResponse <-
      req
        POST
        (http "192.168.1.1" /: "api" /: "system" /: "user_login")
        (ReqBodyJson payload)
        bsResponse
        (cookieJar cookies)
    pure . responseCookieJar $ loginResponse

visitWizardPage :: L.CookieJar -> IO L.CookieJar
visitWizardPage cookies = runReq defaultHttpConfig $ do
    wizardPageRequest <-
      req
        GET
        (http "192.168.1.1" /: "html" /: "wizard" /: "wizard.html")
        NoReqBody
        bsResponse
        (cookieJar cookies)
    let cookieJar = responseCookieJar wizardPageRequest
    pure cookieJar

cleanJsonResponse :: String -> String
cleanJsonResponse str =
  if expectedPrefix `isPrefixOf` str then
      if expectedSuffix `isSuffixOf` str then
        withoutSuffix
      else
        error "Unexpected response suffix"
  else error $ "Response doesn't contain expected prefix `" ++ expectedPrefix ++ "'"
  where
    expectedPrefix = "while(1); /*"
    withoutPrefix = drop (length expectedPrefix) str
    expectedSuffix = "*/" :: String
    withoutSuffix = take (length withoutPrefix - length expectedSuffix) withoutPrefix

data Host = Host
  {
    hostName :: !String
  , active :: !Bool
  , ipAddress :: !String
  } deriving (Show, Generic)

instance ToJSON Host where
  toEncoding = genericToEncoding defaultOptions

instance FromJSON Host where
  parseJSON = withObject "Host" $ \h -> Host
        <$> h .: "HostName"
        <*> h .: "Active"
        <*> h .: "IPAddress"

parseHostsResponse :: String -> [Host]
parseHostsResponse response =
  case decode . BL.pack . cleanJsonResponse $ response :: Maybe [Host] of
    Just hosts -> hosts
    Nothing -> error "Failed to parse hosts response"

loadHosts :: L.CookieJar -> IO String
loadHosts cookies = runReq defaultHttpConfig $ do
    hostsRequest <-
      req
        GET
        (http "192.168.1.1" /: "api" /: "system" /: "HostInfo")
        NoReqBody
        bsResponse
        (cookieJar cookies)
    let responseBody_ = byteStringToString $ responseBody hostsRequest
    pure responseBody_

main :: IO ()
main = do
  cfg <- loadConfig
  (tokens, cookies) <- visitStartPage
  cookies2 <- executeLogin cfg tokens cookies
  cookies3 <- visitWizardPage cookies2
  hostsResponse <- loadHosts cookies3
  let parsedHosts = parseHostsResponse hostsResponse
  let targetHost = find (\Host {..} -> hostName == deviceName cfg) parsedHosts
  let activeHostsCount = length $ filter active parsedHosts
  let onlineHosts = intercalate ", " . map hostName . filter active $ parsedHosts
  case targetHost of
    Just Host {..} | active -> do
      putStrLn ipAddress
    Just Host {..} -> do
      putStrLn $ "Host '" ++ deviceName cfg ++ "' is not active"
      putStrLn $ show activeHostsCount ++ " devices online: " ++ onlineHosts
    Nothing -> do
      putStrLn $ "Device '" ++ deviceName cfg ++ "' is unknown"
      putStrLn $ show activeHostsCount ++ " devices online: " ++ onlineHosts