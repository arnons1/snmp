{-# LANGUAGE OverloadedStrings #-}
module  Network.Protocol.Type where

import Data.Text (Text, cons, take)
import Data.Text.IO (readFile)
import qualified Data.Text as T
import Network.Protocol.Snmp (OID)
import Data.Attoparsec.Text
import Control.Applicative
import Control.Monad (void)
import Prelude hiding (takeWhile, readFile, take)

data Mib = Mib
  { mibGroup :: Text
  , mibName :: Text
  , mibType :: MibType
  , syntax :: Maybe MibSyntax
  , hint   :: Maybe Hint
  , units  :: Maybe Units
  , access :: Maybe MaxAccess
  , status :: Maybe MibStatus
  , index  :: Maybe AIndex
  , description :: Maybe Text
  , oids :: OID
  } deriving Show

mibP :: Parser Mib
mibP = Mib <$> (comment *> mibGroupP )
           <*> (comment *> mibNameP )
           <*> (comment *> mibTypeP )
           <*> (comment *> syntaxP )
           <*> (comment *> hintP )
           <*> (comment *> unitsP )
           <*> (comment *> accessP) 
           <*> (comment *> statusP )
           <*> (comment *> aIndexP )
           <*> (comment *> objectsP *> descriptionP  <* defVal)
           <*> (comment *> oidsP)

mibGroupP :: Parser Text
mibGroupP = do
    h <- satisfy (inClass "A-Z")
    t <- takeWhile (/= ':')
    void $ char ':'
    void $ char ':'
    pure $ cons h t

mibNameP :: Parser Text
mibNameP = do
    h <- takeWhile (not . isEndOfLine)
    el
    void $ string h
    sp
    pure h

mibTypeP :: Parser MibType
mibTypeP = "OBJECT-TYPE" *> pure ObjectType <* el
       <|> "OBJECT-IDENTITY" *> pure ObjectIdentity <* el
       <|> "OBJECT-GROUP" *> pure ObjectGroup <* el
       <|> "NOTIFICATION-TYPE" *> pure NotificationType <* el
       <|> "MODULE-IDENTITY" *> pure ModuleIdentity <* el
       <|> "MODULE-COMPLIANCE" *> pure ModuleCompliance <* el
       <|> "type_23" *> pure Type23 <* el

comment :: Parser ()
comment = skipMany $ do
    sp
    void $ string "--"
    skipWhile (not . isEndOfLine)
    endOfLine

data MibType = ModuleCompliance
             | ModuleIdentity
             | NotificationType
             | ObjectGroup
             | ObjectIdentity
             | ObjectType
             | Type23
             deriving (Show, Eq)

syntaxP :: Parser (Maybe MibSyntax)
syntaxP = (Just <$> (sp *> "SYNTAX" *> sp *> syntaxP')) <|> pure Nothing

syntaxP' :: Parser MibSyntax
syntaxP' = sIntegerWithRange <|> sIntegerWithDict <|> sInteger32WithRange <|> sInteger32WithRangeAndAlt 
    <|> sOctetStringWithRangeP <|> sOctetStringWithAltP <|> sOctetStringWithLengthP
    <|> sUnsignedWithRangeP <|> sUnsignedWithRangeAndAltP
    <|> sBitsP <|> sSimple
       where
       sSimple = sCounter32P <|> sCounter64P <|> sIntegerP <|> sInteger32P <|> sIpAddressP <|> sOctetStringP <|> sNetworkAddressP <|> sOpaqueP
             <|> sOpaqueUCDP <|> sTimeTicksP <|> sUnsignedP <|> sObjectIdentifierP <|> sGaude32P 
       sCounter32P = "Counter32" *> el *> pure SCounter32
       sCounter64P = "Counter64" *> el *> pure SCounter64
       sGaude32P = "Gauge32" *> el *> pure SGauge32
       sIntegerP = "INTEGER" *> el *> pure SInteger
       sInteger32P = "Integer32" *> el *> pure SInteger32
       sIpAddressP = "IpAddress" *> el *> pure SIpAddress
       sOctetStringP = "OCTET STRING" *> el *> pure SOctetString
       sNetworkAddressP = "NetworkAddress" *> el *> pure SNetworkAddress
       sOpaqueP = "Opaque" *> el *> pure SOpaque
       sOpaqueUCDP = "Opaque (UCD-SNMP-MIB)" *> el *> pure SOpaqueUCD
       sTimeTicksP = "TimeTicks" *> el *> pure STimeTicks
       sUnsignedP = "Unsigned32" *> el *> pure SUnsigned
       sObjectIdentifierP = "OBJECT IDENTIFIER" *> pure SObjectIdentifier <* el
       sIntegerWithRange = SIntegerWithRange <$> ("INTEGER" *> sp *> char '(' *> num <* "..") <*> num <* char ')' <* el
       sIntegerWithDict = SIntegerWithDict <$> ("INTEGER" *> sp *> char '{' *> pair `sepBy1` char ',') <* char '}' <* el
       sInteger32WithRange = SInteger32WithRange <$> ("Integer32" *> sp *> char '(' *> num <* "..") <*> num <* char ')' <* el
       sInteger32WithRangeAndAlt = SInteger32WithRangeAndAlt <$> ("Integer32" *> sp *> char '(' *> num <* sp <* char '|' <* sp)
            <*> (num <* "..") <*> num <* char ')' <* el
       sOctetStringWithRangeP = SOctetStringWithRange <$> ("OCTET STRING (" *> num <* "..") <*> num <* ")" <* el
       sOctetStringWithLengthP = SOctetStringWithLength <$> ("OCTET STRING (" *> num <* ")" <* el)
       sOctetStringWithAltP = SOctetStringWithAlt <$> ("OCTET STRING (" *> num <* sp <* char '|' <* sp) <*> num <* char ')' <* el
       sUnsignedWithRangeP = SUnsignedWithRange <$> ("Unsigned32 (" *> num <* "..") <*> num <* char ')' <* el
       sUnsignedWithRangeAndAltP = SUnsignedWithRangeAndAlt <$> ("Unsigned32 (" *> num <* sp <* char '|' <* sp) <*> (num <* "..")
           <*> num <* char ')' <* el
       sBitsP = SBits <$> ("BITS {" *>  pair `sepBy1` char ',' <* char '}' <* el)
       pair :: Parser (Int, Text)
       pair = swap <$> ((,) <$> (sp *> takeWhile1 (/= '(')) <* char '(' <*> (num <* char ')'))

swap :: (a,b) -> (b,a)
swap (a,b) = (b,a)

num :: Parser Int
num = signed decimal

el :: Parser ()
el = sp *> endOfLine

sp :: Parser ()
sp = many' (char '\t' <|> char ' ') *> pure ()

data MibSyntax =
    SCounter32
    | SCounter64
    | SGauge32
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

hintP :: Parser  (Maybe Hint)
hintP = (Just <$> (Hint <$> (sp *> "DISPLAY-HINT" *> sp *> char '"' *> takeWhile1 (/= '"')) <* char '"' <* el))
    <|> pure Nothing

data Hint = Hint Text 
    deriving (Show, Eq)

accessP :: Parser (Maybe MaxAccess)
accessP = (Just <$> variant) <|> pure Nothing
    where
    variant = sp *> "MAX-ACCESS" *> sp *> (sAccessibleForNotify <|> sNotAccessible <|> sReadCreate <|> sReadOnly <|> sReadWrite) <* el
    sAccessibleForNotify = "accessible-for-notify" *> pure AccessibleForNotify
    sNotAccessible = "not-accessible" *> pure NotAccessible
    sReadCreate = "read-create"*> pure ReadCreate
    sReadOnly = "read-only" *> pure ReadOnly
    sReadWrite = "read-write" *> pure ReadWrite

data MaxAccess = AccessibleForNotify
               | NotAccessible
               | ReadCreate
               | ReadOnly
               | ReadWrite
               deriving (Show, Eq)

statusP :: Parser (Maybe MibStatus)
statusP = (Just <$> variant) <|> pure Nothing
    where
    variant = sp *> "STATUS" *> sp *> (sCurrent <|> sDeprecated <|> sObsolete <|> sMandatory) <* el
    sCurrent = "current" *> pure Current
    sDeprecated = "deprecated" *> pure Deprecated
    sObsolete = "obsolete" *> pure Obsolete
    sMandatory = "mandatory" *> pure Mandatory

data MibStatus = Current
               | Deprecated
               | Obsolete
               | Mandatory
               deriving (Show, Eq)

aIndexP :: Parser (Maybe AIndex)
aIndexP = (Just <$> variant) <|> pure Nothing
    where
    variant = IN <$> (sp *> "INDEX" *> sp *> char '{' *> (vs `sepBy1` char ',') <* sp <* char '}' <* el)
        <|> AU <$> (sp *> "AUGMENTS" *> sp *> char '{' *> ((sp *> takeTill (inClass " ,")) `sepBy1` char ',') <* sp <* char '}' <* el)
    vs = Implied <$> (sp *> "IMPLIED" *> sp *> takeTill (inClass " ,"))
        <|> Index <$> (sp *> takeTill (inClass " ,"))



data Index = Index Text
           | Implied Text
           deriving (Show, Eq)

data Augments = Augments Text
              deriving (Show, Eq)

data AIndex = AU [Text]
            | IN [Index]
            deriving (Show, Eq)

newtype Units = Units Text deriving (Show, Eq)

unitsP :: Parser (Maybe Units)
unitsP = (Just <$> units') <|> pure Nothing
    where
    units' = Units <$> (sp *> "UNITS" *> sp *> char '"' *> takeWhile1 (/= '"') <* char '"' <* el)

objectsP :: Parser ()
objectsP = sp *> "OBJECTS" *> takeWhile (not . isEndOfLine) *> endOfLine <|> pure () 

defVal :: Parser ()
defVal = (sp *> "DEFVAL" *> takeWhile (not . isEndOfLine) *> endOfLine) <|> pure ()

descriptionP :: Parser (Maybe Text)
descriptionP = (Just <$> desc) <|> pure Nothing 
    where
    desc = sp *> "DESCRIPTION" *> sp *> char '"' *> takeWhile (/= '"') <* char '"' <* el

oidsP :: Parser OID
oidsP = frp <$> ("::=" *> sp *> char '{'  *> manyTill oi (char '}') )
    where
    oi :: Parser Int
    oi = (sp *> num <* sp) <|> (sp *> takeWhile1 (/= '(') *> char '(' *> num <* char ')' <* sp)

frp :: [Int] -> OID
frp = map fromIntegral

