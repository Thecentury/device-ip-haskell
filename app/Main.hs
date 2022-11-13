{-# LANGUAGE OverloadedStrings #-}

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
import Data.Text as T ( unpack )
import Data.Text.Encoding as T ( decodeUtf8 )
import Data.Text.IO as T ()
import qualified Network.HTTP.Client as L ( CookieJar )

import Text.HandsomeSoup ( (!), css, parseHtml )
import Text.XML.HXT.Core ( (>>>), runX )

byteStringToString :: ByteString -> String
byteStringToString = T.unpack . T.decodeUtf8

requiredMeta :: String -> [(String, String)] -> String
requiredMeta key meta = case lookup key meta of
  Just value -> value
  Nothing    -> error $ "Required meta tag not found: " ++ key

visitStartPage :: IO (String, String, L.CookieJar)
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

  pure (csrfToken, csrfParam, cookies)

main :: IO ()
main = do
  (csrfToken, csrfParam, cookie) <- visitStartPage
  putStrLn $ "csrf_token = " ++ csrfToken
  putStrLn $ "csrf_param = " ++ csrfParam
  print cookie
