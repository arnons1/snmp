{-# LANGUAGE OverloadedStrings #-}
module  Network.Protocol.Type where

import Data.Text (Text, cons, take)
import Data.Text.IO (readFile)
import Network.Protocol.Snmp (OIDS)
import Data.Attoparsec.Text
import Control.Applicative
import Data.Monoid ((<>))
import Control.Monad (void)
import Prelude hiding (takeWhile, readFile, take)

mibP :: Parser Mib
mibP = Mib <$> mibGroupP <*> mibNameP <*> mibTypeP <*> syntaxP <*> hintP <*> accessP <*> statusP <*> descriptionP <*> oidsP

mibGroupP :: Parser Text
mibGroupP = do
    h <- satisfy (inClass "A-Z")
    t <- takeWhile (/= ':')
    void $ char ':'
    void $ char ':'
    return $ cons h t

mibNameP :: Parser Text
mibNameP = do
    h <- takeWhile (not . isEndOfLine)
    void endOfLine
    void $ string h
    void space
    return h

mibTypeP :: Parser MibType
mibTypeP = "OBJECT-TYPE" *> pure ObjectType
       <|> "OBJECT-IDENTITY" *> pure ObjectIdentity
       <|> "OBJECT-GROUP" *> pure ObjectGroup
       <|> "NOTIFICATION-TYPE" *> pure NotificationType
       <|> "MODULE-IDENTITY" *> pure ModuleIdentity
       <|> "MODULE-COMPLIANCE" *> pure ModuleCompliance

syntaxP = undefined
hintP = undefined
accessP = undefined
statusP = undefined
descriptionP = undefined
oidsP = undefined

data Mib = Mib
  { mibGroup :: Text
  , mibName :: Text
  , mibType :: MibType
  , syntax :: Maybe MibSyntax
  , hint   :: Maybe MibHint
  , access :: Maybe MaxAccess
  , status :: Maybe MibStatus
  , description :: Maybe Text
  , oids :: OIDS
  } deriving Show

data MibType = ModuleCompliance
             | ModuleIdentity
             | NotificationType
             | ObjectGroup
             | ObjectIdentity
             | ObjectType
             deriving (Show, Eq)


data MibSyntax =
    SCounter32
    | SCounter64
    | SGaude32
    | SInteger
    | SIntegerWithRange Int Int
    | SIntegerWithDict [(Int, Text)]
    | SInteger32 
    | SInteger32WithRange Int Int
    | SInteger32WithRangeAndAlt Int Int Int
    | SIpAddress
    | SNetworkAddress
    | SObjectIdentifier
    | SOctetString
    | SOctetStringWithRange Int Int
    | SOctetStringWithLength Int
    | SOctetStringWithAlt Int Int
    | SOpaque
    | SOpaqueUCD
    | STimeTicks
    | SUnsigned 
    | SUnsignedWithRange Int Int
    | SUnsignedWithRangeAndAlt Int Int Int
    | SBits [(Int, Text)]
    deriving (Show, Eq)

data MibHint =
    Hint1x
    | Hint255a
    | Hint255t
    | HintDate
    | Hint2x
    | Hintd
    deriving (Show, Eq)

data MaxAccess = AccessibleForNotify
               | NotAccessible
               | ReadCreate
               | ReadOnly
               | ReadWrite
               deriving (Show, Eq)

data MibStatus = Current
               | Deprecated
               | Obsolete
               | Mandatory
               deriving (Show, Eq)



