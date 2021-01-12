import unittest
import string
import logging
from _groupsig import ffi

from pygroupsig import groupsig
from pygroupsig import grpkey
from pygroupsig import mgrkey
from pygroupsig import memkey
from pygroupsig import identity
from pygroupsig import message
from pygroupsig import signature
from pygroupsig import gml
from pygroupsig import constants

# Tests for group operations
class TestGroupOps(unittest.TestCase):

    # Non-test functions
    def addMember(self):
        msg1 = groupsig.join_mgr(0, self.mgrkey, self.grpkey, gml = self.gml)
        msg2 = groupsig.join_mem(1, self.grpkey, msgin = msg1)
        usk = msg2['memkey']
        msg3 = groupsig.join_mgr(2, self.mgrkey, self.grpkey, msg2['msgout'], gml = self.gml)
        msg4 = groupsig.join_mem(3, self.grpkey, msgin = msg3, memkey = usk)
        usk = msg4['memkey']
        self.memkeys.append(usk)

    def setUp(self):
        groupsig.init(constants.PS16_CODE, 0)
        group = groupsig.setup(constants.PS16_CODE)
        self.code = constants.PS16_CODE
        self.mgrkey = group['mgrkey']
        self.grpkey = group['grpkey']
        self.gml = group['gml']
        self.memkeys = []
        
    def tearDown(self):
        groupsig.clear(self.code)

    # Creates a group
    def test_groupCreate(self):
        self.assertNotEqual(self.grpkey, ffi.NULL)
        self.assertNotEqual(self.mgrkey, ffi.NULL)
        self.assertEqual(groupsig.get_joinseq(constants.PS16_CODE), 3)
        self.assertEqual(groupsig.get_joinstart(constants.PS16_CODE), 0)   

    # Adds one member
    def test_addMember(self):
        n_members = len(self.memkeys)
        self.addMember()
        self.assertEqual(len(self.memkeys), n_members+1)
        self.assertNotEqual(self.memkeys[n_members], ffi.NULL)
        
    # Accepts a valid signature for a message passed as a string
    def test_acceptValidSignatureString(self):
        self.addMember()
        sig = groupsig.sign("Hello, World!", self.memkeys[0], self.grpkey)
        b = groupsig.verify(sig, "Hello, World!", self.grpkey)
        self.assertTrue(b)

    # Rejects a valid signature for a different message, also passed as a string
    def test_rejectValidSignatureWrongMessageString(self):
        self.addMember()
        sig = groupsig.sign("Hello, World!", self.memkeys[0], self.grpkey)
        b = groupsig.verify(sig, "Hello, Worlds!", self.grpkey)
        self.assertFalse(b)

    # Accepts a valid signature for a message passed as a byte array
    def test_acceptValidSignatureBytes(self):
        self.addMember()
        sig = groupsig.sign(b"Hello, World!", self.memkeys[0], self.grpkey)
        b = groupsig.verify(sig, b"Hello, World!", self.grpkey)
        self.assertTrue(b)

    # Rejects a valid signature for a different message, also passed as a byte array
    def test_rejectValidSignatureWrongMessageBytes(self):
        self.addMember()
        sig = groupsig.sign(b"Hello, World!", self.memkeys[0], self.grpkey)
        b = groupsig.verify(sig, b"Hello, Worlds!", self.grpkey)
        self.assertFalse(b)

    # Successfully opens a signature
    def test_openSignature(self):
        self.addMember()
        self.addMember()
        sig = groupsig.sign(b"Hello, World!", self.memkeys[1], self.grpkey)
        gsopen = groupsig.open(sig, self.mgrkey, self.grpkey, gml = self.gml)
        self.assertEqual(gsopen["index"], 1)
        proof = gsopen['proof']
        b = groupsig.open_verify(proof, sig, self.grpkey)
        self.assertTrue(b)
        
# Tests for signature operations
class TestSignatureOps(unittest.TestCase):

    # Non-test functions
    def addMember(self):
        msg1 = groupsig.join_mgr(0, self.mgrkey, self.grpkey, gml = self.gml)
        msg2 = groupsig.join_mem(1, self.grpkey, msgin = msg1)
        usk = msg2['memkey']
        msg3 = groupsig.join_mgr(2, self.mgrkey, self.grpkey, msg2['msgout'], gml = self.gml)
        msg4 = groupsig.join_mem(3, self.grpkey, msgin = msg3, memkey = usk)
        usk = msg4['memkey']
        self.memkeys.append(usk)
        
    # Creates a group, adds a member and generates a signature
    def setUp(self):
        groupsig.init(constants.PS16_CODE, 0)
        group = groupsig.setup(constants.PS16_CODE)
        self.code = constants.PS16_CODE
        self.mgrkey = group['mgrkey']
        self.grpkey = group['grpkey']
        self.gml = group['gml']
        self.memkeys = []
        self.addMember()
        self.sig = groupsig.sign("Hello, World!", self.memkeys[0], self.grpkey)
        
    def tearDown(self):
        groupsig.clear(self.code)

    # Exports and reimports a signature, and it verifies correctly
    def test_sigExportImport(self):
        sig_str = signature.signature_export(self.sig)
        sig = signature.signature_import(self.code, sig_str)
        b = groupsig.verify(sig, "Hello, World!", self.grpkey)
        self.assertTrue(b)
                        
    # Prints a string (this just checks the produced string is not empty)
    def test_sigToString(self):
        sig_str = signature.signature_to_string(self.sig)
        self.assertGreater(len(sig_str), 0)
        self.assertTrue(set(sig_str).issubset(set(string.printable)))

# Tests for group key operations
class TestGrpkeyOps(unittest.TestCase):

    # Creates a group, adds a member and generates a signature
    def setUp(self):
        groupsig.init(constants.PS16_CODE, 0)
        group = groupsig.setup(constants.PS16_CODE)
        self.code = constants.PS16_CODE
        self.mgrkey = group['mgrkey']
        self.grpkey = group['grpkey']
        self.gml = group['gml']
        
    def tearDown(self):
        groupsig.clear(self.code)

    # Exports and reimports a group key
    def test_grpkeyExportImport(self):
        grpkey_str = grpkey.grpkey_export(self.grpkey)
        gpk = grpkey.grpkey_import(self.code, grpkey_str)
        # This is quite useless, as import returns an exception if the FFI
        # method returns ffi.NULL. Maybe implementing a cmp function for
        # grp keys would be good for testing this (and also in general?)
        self.assertIsNot(ffi.NULL, gpk)

# Tests for manager key operations
class TestManagerkeyOps(unittest.TestCase):

    # Creates a group, adds a member and generates a signature
    def setUp(self):
        groupsig.init(constants.PS16_CODE, 0)
        group = groupsig.setup(constants.PS16_CODE)
        self.code = constants.PS16_CODE
        self.mgrkey = group['mgrkey']
        self.grpkey = group['grpkey']
        self.gml = group['gml']
        
    def tearDown(self):
        groupsig.clear(self.code)

    # Exports and reimports an manager key
    def test_mgrkeyExportImport(self):
        mgrkey_str = mgrkey.mgrkey_export(self.mgrkey)
        ikey = mgrkey.mgrkey_import(self.code, mgrkey_str)
        # This is quite useless, as import returns an exception if the FFI
        # method returns ffi.NULL. Maybe implementing a cmp function for
        # manager keys would be good for testing this (and also in general?)
        self.assertIsNot(ffi.NULL, ikey)

# Tests for member key operations
class TestMemkeyOps(unittest.TestCase):

    # Non-test functions
    def addMember(self):
        msg1 = groupsig.join_mgr(0, self.mgrkey, self.grpkey, gml = self.gml)
        msg2 = groupsig.join_mem(1, self.grpkey, msgin = msg1)
        usk = msg2['memkey']
        msg3 = groupsig.join_mgr(2, self.mgrkey, self.grpkey, msg2['msgout'], gml = self.gml)
        msg4 = groupsig.join_mem(3, self.grpkey, msgin = msg3, memkey = usk)
        usk = msg4['memkey']
        self.memkey = usk
        
    # Creates a group, adds a member and generates a signature
    def setUp(self):
        groupsig.init(constants.PS16_CODE, 0)
        group = groupsig.setup(constants.PS16_CODE)
        self.code = constants.PS16_CODE
        self.mgrkey = group['mgrkey']
        self.grpkey = group['grpkey']
        self.gml = group['gml']
        self.addMember()
        
    def tearDown(self):
        groupsig.clear(self.code)

    # Exports and reimports a member key
    def test_memkeyExportImport(self):
        memkey_str = memkey.memkey_export(self.memkey)
        mkey = memkey.memkey_import(self.code, memkey_str)
        # This is quite useless, as import returns an exception if the FFI
        # method returns ffi.NULL. Maybe implementing a cmp function for
        # mem keys would be good for testing this (and also in general?)
        self.assertIsNot(ffi.NULL, mkey)

# Tests for GML operations
class TestGmlOps(unittest.TestCase):

    # Non-test functions
    def addMember(self):
        msg1 = groupsig.join_mgr(0, self.mgrkey, self.grpkey, gml = self.gml)
        msg2 = groupsig.join_mem(1, self.grpkey, msgin = msg1)
        usk = msg2['memkey']
        msg3 = groupsig.join_mgr(2, self.mgrkey, self.grpkey, msg2['msgout'], gml = self.gml)
        msg4 = groupsig.join_mem(3, self.grpkey, msgin = msg3, memkey = usk)
        usk = msg4['memkey']
        self.memkey = usk
        
    # Creates a group, adds a member and generates a signature
    def setUp(self):
        groupsig.init(constants.PS16_CODE, 0)
        group = groupsig.setup(constants.PS16_CODE)
        self.code = constants.PS16_CODE
        self.mgrkey = group['mgrkey']
        self.grpkey = group['grpkey']
        self.gml = group['gml']
        self.addMember()
        
    def tearDown(self):
        groupsig.clear(self.code)

    # Exports and reimports a member key
    def test_gmlExportImport(self):
        gml_str = gml.gml_export(self.gml)
        _gml = gml.gml_import(self.code, gml_str)
        # This is quite useless, as import returns an exception if the FFI
        # method returns ffi.NULL. Maybe implementing a cmp function for
        # GMLs would be good for testing this (and also in general?)
        self.assertIsNot(ffi.NULL, _gml)
                                
# Define test suites
def suiteGroupOps():
    suiteGroupOps = unittest.TestSuite()    
    suiteGroupOps.addTest(WidgetTestCase('test_groupCreate'))
    suiteGroupOps.addTest(WidgetTestCase('test_addMember'))
    suiteGroupOps.addTest(WidgetTestCase('test_acceptValidSignatureString'))
    suiteGroupOps.addTest(WidgetTestCase('test_rejectValidSignatureWrongMessageString'))
    suiteGroupOps.addTest(WidgetTestCase('test_acceptValidSignatureBytes'))
    suiteGroupOps.addTest(WidgetTestCase('test_rejectValidSignatureWrongMessageBytes'))
    suiteGroupOps.addTest(WidgetTestCase('test_openSignature'))
    return suiteGroupOps
        
def suiteSigOps():
    suiteSigOps = unittest.TestSuite()    
    suiteSigOps.addTest(WidgetTestCase('test_sigExportImport'))
    suiteSigOps.addTest(WidgetTestCase('test_sigToString'))
    return suiteSigOps

def suiteGrpkeyOps():
    suiteGrpkeyOps = unittest.TestSuite()    
    suiteGrpkeyOps.addTest(WidgetTestCase('test_grpkeyExportImport'))
    return suiteGrpkeyOps

def suiteManagerkeyOps():
    suiteManagerkeyOps = unittest.TestSuite()    
    suiteManagerkeyOps.addTest(WidgetTestCase('test_mgrkeyExportImport'))
    return suiteManagerkeyOps

def suiteMemkeyOps():
    suiteMemkeyOps = unittest.TestSuite()    
    suiteMemkeyOps.addTest(WidgetTestCase('test_memkeyExportImport'))
    return suiteMemkeyOps

def suiteGmlOps():
    suiteGmlOps = unittest.TestSuite()    
    suiteGmlOps.addTest(WidgetTestCase('test_gmlExportImport'))
    return suiteGmlOps
        
if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    runner.run(suiteGroupOps())
    runner.run(suiteSigOps())
    runner.run(suiteGrpkeyOps())
    runner.run(suiteManagerkeyOps())
    runner.run(suiteMemkeyOps())
    runner.run(suiteGmlOps())
