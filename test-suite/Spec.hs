import Test.Hspec

import Test.Hspec
import qualified Wiretap.Main as W

main :: IO ()
main = hspec $ do
  describe "wiretap-tools" $ do
    it "should run on 'bufwriter'" $ do
      W.mainWithArgs ["dataraces", "-v", "--chunk-size", "1000", "test/bufwriter/wiretap.hist"]
