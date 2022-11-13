{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

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
      NoReqBody(NoReqBody), responseCookieJar )
import Data.Aeson ()
import Control.Monad.IO.Class ()
import Data.ByteString as B ( ByteString )
import qualified Data.ByteString.Char8 as BS (pack, unpack)
import Data.Text as T ( unpack )
import Data.Text.Encoding as T ( decodeUtf8 )
import Data.Text.IO as T ()
import qualified Network.HTTP.Client as L ( CookieJar )
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Data.ByteString.Base64 as Base64 ( encode )

import Text.HandsomeSoup ( (!), css, parseHtml )
import Text.XML.HXT.Core ( (>>>), runX )
import System.Environment (getEnv)
import Data.ByteString.Builder (toLazyByteString, byteStringHex)
import Data.ByteString.Lazy (toStrict)

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
  { csrfToken :: String
  , csrfParam :: String
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
        mempty -- query params, headers, explicit port number, etc.
    let status = responseStatusCode startPageRequest
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
  { userName :: String
  , password :: String
  , deviceName :: String
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

main :: IO ()
main = do
  cfg <- loadConfig

  putStrLn $ "Password hash: " ++ (encodeBase64 . computeHash $ password cfg)

  (tokens, cookie) <- visitStartPage
  putStrLn $ "csrf_token = " ++ csrfToken tokens
  putStrLn $ "csrf_param = " ++ csrfParam tokens

  putStrLn $ "Password hash: " ++ encodePassword cfg tokens
  print cookie
