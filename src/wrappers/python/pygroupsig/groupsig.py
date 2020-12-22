from _groupsig import lib, ffi
from . import constants

#from array import array

def hello_world():
    """
    Prints the string 'Hello, World' in the standard output.
    """    
    lib.groupsig_hello_world()
    return

def init(scheme, seed=0):
    """
    Initializes the system wide variables needed to manage group signature
    schemes of the given type, including the system random number generator.
    Optional parameters may be ignored in some schemes.

    Parameters:
        scheme: The code specifying the type of scheme that will be used.
        seed: Optional parameter. May be used to seed the PRNG.
    Returns:
        void. On error, an Exception is thrown.
    """    
    if lib.groupsig_init(scheme, seed) == lib.IERROR:
        raise Exception('Error initializing groupsig environment.')

    return

def clear(scheme):
    """
    Clears any system wide variables used to manage group signature schemes of 
    the given type and the configuration options that some schemes may have. 

    Parameters:
        scheme: The code specifying the type of scheme that will be used.
        config: Scheme-specific configuration options.
    Returns:
        void. On error, an Exception is thrown.
    """    

    if lib.groupsig_clear(scheme) == lib.IERROR:
        raise Exception('Error clearing groupsig environment.')

    return

def setup(scheme, grpkey=ffi.NULL, seed=0):
    """
    Generates the group and/or manager(s) key(s) and/or GML(s) of schemes of the
    given type. Note that the behaviour of this function varies depending on the
    scheme. Check the documentation of the specific scheme in the core library
    (https://github.com/IBM/libgroupsig).
    Optional parameters may be ignored in some schemes.

    Parameters:
        scheme: The code specifying the type of scheme.
        grpkey: Optional parameter. Some schemes require several calls to 
                the setup function with a (partially filled or pre-filled)
                group key.
        seed: Optional parameter. May be used to seed the PRNG.
    Returns:
        An object containing a subset of:
            grpkey: A (possibly partially) initialized group key.
            mgrkey: A (possibly partially) initialized manager key.
            gml: A (possibly partially) initialized GML.
            config: A (possibly partially) initialize configuration structure.
        Unused fields may be set to NULL.
        An exception is thrown on error.
    """        

    if grpkey == ffi.NULL:
        _grpkey = lib.groupsig_grp_key_init(scheme)
    else:
        _grpkey = grpkey
    mgrkey = lib.groupsig_mgr_key_init(scheme)
    gml = lib.gml_init(scheme)
    if lib.groupsig_init(scheme, seed) == lib.IERROR:
        raise Exception('Error initializing scheme ' + scheme)
    
    if lib.groupsig_setup(scheme, _grpkey, mgrkey, gml) == lib.IERROR:
        raise Exception('Error setting up scheme ' + scheme)

    return {
        'grpkey': _grpkey,
        'mgrkey': mgrkey,
        'gml': gml
    }

def get_joinseq(scheme):
    """
    Returns the number of messages exchanged between the manager and member
    during a join process of schemes of the given type

    Parameters:
        scheme: The code specifying the type of scheme.
    Returns:
        The number of messages to be exchanged.
    """
    msgs = ffi.new("uint8_t *")    

    if lib.groupsig_get_joinseq(scheme, msgs) == lib.IERROR:
        raise Exception('Error getting number of messages in Join.')

    return msgs[0]

def get_joinstart(scheme):
    """
    Informs whether the manager of the member initiates the join process.

    Parameters:
        scheme: The code specifying the type of scheme.
    Returns:
        0 if the manager starts the join process, 1 if the member starts.
    """

    start = ffi.new("uint8_t *")

    if lib.groupsig_get_joinstart(scheme, start) == lib.IERROR:
        raise Exception('Error getting starting party in Join.')
    
    return start[0]

def join_mgr(step, mgrkey, grpkey, msgin = ffi.NULL, gml = ffi.NULL):
    """
    Runs a manager step of the join process. As a result of this function,
    a message of the join process will be generated.
    Optional parameters may be ignored in some schemes.

    Parameters:
        step: The step of the join process to execute.
        mgrkey: The manager key.
        grpkey: The group key.
        msgin: Optional. The input message from a previous step of the join
               process.
        gml: Optional. The GML.
    Returns:
        A native object (of message type) containing the next message to send, 
        if any. On error, an exception is thrown.
    """

    msgout = ffi.new("message_t **")
    msgout[0] = ffi.NULL

    if lib.groupsig_join_mgr(msgout, gml, mgrkey, step, msgin, grpkey) == lib.IERROR:
        raise Exception('Error running join_mgr operation.')

    return msgout[0]

def join_mem(step, grpkey, msgin = ffi.NULL, memkey = ffi.NULL):
    """
    Runs a member step of the join process. As a result of this function,
    a message of the join process will be generated. In the final member call,
    the member key will also be returned.
    Optional parameters may be ignored in some schemes.

    Parameters:
        step: The step of the join process to execute.
        grpkey: The group key.
        msgin: Optional. The input message from a previous step of the join
               process.
        memkey: Optional. A (possibly partially filled) member key.
    Returns:
        An object containing:
            msgout: A native object (of message type) with the message to send
                    to the manager.
            memkey: When step is the last step in the join process, the final
                    member key.
        On error, an exception is thrown.
    """    

    msgout = ffi.new("message_t **")
    msgout[0] = ffi.NULL

    if memkey == ffi.NULL:
        _memkey = lib.groupsig_mem_key_init(grpkey.scheme)
    else:
        _memkey = memkey
        
    if lib.groupsig_join_mem(msgout, _memkey, step, msgin, grpkey) == lib.IERROR:
        raise Exception('Error running join_mem operation.')

    return {
        'msgout' : msgout[0],
        'memkey' : _memkey
    }

def sign(msg, memkey, grpkey, seed=0):
    """
    Produces a group signature.

    Parameters:
        msg: The message to sign. May be of type _bytes_ or a UTF-8 string.
        memkey: The member key.
        grpkey: The group key.
        seed: Optional. May be used to (re-)seed the PRNG. 
    Returns:
        A native object containing the group signature. On error, an exception 
        is thrown.
    """    
    
    sig = lib.groupsig_signature_init(memkey.scheme)

    if isinstance(msg, bytes):
        _msg = lib.message_from_bytes(msg, len(msg))
    else:
        _msg = lib.message_from_string(msg.encode('utf8'))
        
    if lib.groupsig_sign(sig, _msg, memkey, grpkey, seed) == lib.IERROR:
        raise Exception('Error signing message.')

    return sig

def verify(sig, msg, grpkey):
    """
    Verifies a group signature.

    Parameters:
        sig: The signature to verify.
        msg: The signed message. May be of type _bytes_ or a UTF-8 string.
        grpkey: The group key.
    Returns:
        True if the signature is valid, False otherwise. On error, an exception 
        is thrown.
    """    
    
    _b = ffi.new("uint8_t *")

    if isinstance(msg,bytes):
        _msg = lib.message_from_bytes(msg,len(msg))
    else:
        _msg = lib.message_from_string(msg.encode('utf8'))
    
    if lib.groupsig_verify(_b, sig, _msg, grpkey) == lib.IERROR:
        raise Exception('Error verifying message.')
    else:
        if _b[0] == 1:
            return True
        if _b[0] == 0:
            return False

def verify_batch(sigs, msgs, grpkey):
    """
    Verifies a group signature.

    Parameters:
        sigs: The array of signatures to verify.
        msgs: The array signed messages. Each message may be of type _bytes_ or 
              a UTF-8 string.
        grpkey: The group key.
    Returns:
        True if the signatures are all valid, False otherwise. On error, an 
        exception is thrown.
    """    
    
    _b = ffi.new("uint8_t *")

    _msgs = []
    for i in range(len(msgs)):       
        if isinstance(msgs[i], bytes):
            _msg = lib.message_from_bytes(msgs[i],len(msg[i]))
        else:
            _msg = lib.message_from_string(msgs[i].encode('utf8'))
        _msgs.append(_msg)
    
    if lib.groupsig_verify_batch(_b, sigs, _msgs, len(sigs), grpkey) == lib.IERROR:
        raise Exception('Error verifying message.')
    else:
        if _b[0] == 1:
            return True
        if _b[0] == 0:
            return False        

def open(sig, mgrkey, grpkey, gml=ffi.NULL, crl=ffi.NULL):
    """
    Opens a group signature, in schemes that support it.
    Optional parameters may be ignored in some schemes.

    Parameters:
        sig: The signature to open.
        mgrkey: The opener key.
        grpkey: The group key.
        gml: Optional. The GML.
        crl: Optional. The CRL (Certificate Revocation List).
    Returns:
        A native object with two fields: 
          'index': An integer identifying the signer within the GML. 
          'proof': Optional field. Will be a native object in schemes that
                   provide verifiable openings.
        On error, an exception is thrown.
    """
    
    _index = ffi.new("uint64_t *")
    proof = lib.groupsig_proof_init(sig.scheme)

    if lib.groupsig_open(_index, proof, crl, sig, grpkey, mgrkey, gml) == lib.IERROR:
        raise Exception('Error opening signature')

    return  {
        'index': _index[0],
        'proof': proof
    }

def open_verify(proof, sig, grpkey):

    _b = ffi.new("uint8_t *")
    
    if lib.groupsig_open_verify(_b, proof, sig, grpkey) == lib.IERROR:
        raise Exception('Error verifying open proof')
    else:
        if _b[0] == 1:
            return True
        if _b[0] == 0:
            return False

def blind(grpkey, sig, msg, bldkey=ffi.NULL):
    """
    Blinds a group signature, in schemes that support it.

    Parameters:
        grpkey: The group key.
        sig: The signature to blind.
        msg: The message associated to the signature.
        bldkey: Optional. The key used for blinding. If unspecified, a random
                key will be internally generated and returned.
    Returns:
        An object containing:
            bldkey: The key used to blind the signature.
            bsig: The blinded signature.
        On error, an exception is thrown.
    """
    
    if bldkey == ffi.NULL:
        _bldkey = ffi.new("groupsig_key_t **")
        _bldkey[0] = ffi.NULL
    else:
        _bldkey = ffi.new("groupsig_key_t **")
        _bldkey[0] = bldkey

    bsig = lib.groupsig_blindsig_init(sig.scheme)

    if isinstance(msg,bytes):
        _msg = lib.message_from_bytes(msg,len(msg))
    else:
        _msg = lib.message_from_string(msg.encode('utf8'))
    
    if lib.groupsig_blind(bsig, _bldkey, grpkey, sig, _msg) == lib.IERROR:
        raise Exception('Error blinding signature.')

    if bldkey == ffi.NULL:
        return {
            'bldkey': _bldkey[0],
            'bsig' : bsig
        }

    else:
        return {
            'bldkey': _bldkey,
            'bsig' : bsig
        }

def convert(bsigs, grpkey, bldkey, msg=ffi.NULL, mgrkey=ffi.NULL):
    """
    Converts a set of blinded group signatures, in schemes that support it.
    Optional parameters may be ignored in some schemes.

    Parameters:
        bsigs: An array containing the blinded group signatures.
        grpkey: The group key.
        bldkey: The public part of the blinding keypair.
        msg: Optional. The blinded messages associated to the signatures.
        mgrkey: Optional. The manager key used for conversion.
    Returns:
        An array containing the converted blinded group signatures. On error, an
        exception is thrown.
    """
    _csigs = [
        lib.groupsig_blindsig_init(grpkey.scheme) for i in range(len(bsigs))
    ]
    
    csigs = ffi.new("groupsig_blindsig_t* []", _csigs)

    if lib.groupsig_convert(csigs, bsigs, len(bsigs), grpkey, mgrkey, bldkey, msg) == lib.IERROR:
        raise Exception('Error converting signatures.')
    
    return csigs

def unblind(csig, bldkey, grpkey=ffi.NULL, sig=ffi.NULL):
    """
    Unblinds a blindly converted group signature, for schemes that support it.
    Optional parameters may be ignored in some schemes.

    Parameters:
        csig: A blindly converted group signature.
        bldkey: The blinding keypair.
        grpkey: Optional. The group key.
        sig: Optional. The unblinded group signature.
    Returns:
        An object containing:
            nym: A (possibly pseudonymized) identity of the signer.
            msg: A (possibly obfuscated) signed message.
        On error, an exception is thrown.
    """
    
    msg = lib.message_init()
    nym = lib.identity_init(csig.scheme)

    if lib.groupsig_unblind(nym, sig, csig, grpkey, bldkey, msg) == lib.IERROR:
        raise Exception('Error unblinding signature.')

    return {
        'nym' : ffi.string(lib.identity_to_string(nym)),
        'msg' : ffi.string(lib.message_to_base64(msg))
    }
    return 
