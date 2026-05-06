public class ContractLibraryPrimitives {
  private interface Action {
    void run();
  }

  private static final Address ALICE = Address.fromHex(0,
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  private static final Address BOB = Address.fromHex(0,
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
  private static final Address CAROL = Address.fromHex(0,
      "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
  private static final Bytes32 MINTER_ROLE = Crypto.keccak256(
      "MINTER_ROLE".getBytes());

  private static void expect(boolean value) {
    if (! value) {
      throw new RuntimeException();
    }
  }

  private static void expectRevert(String signature, Action action) {
    try {
      action.run();
      throw new RuntimeException("expected ContractRevertException");
    } catch (ContractRevertException expected) {
      expect(expected.signature().equals(signature));
      expect(expected.selector().equals(ABI.selector(signature)));
    }
  }

  private static void expectIllegalArgument(Action action) {
    try {
      action.run();
      throw new RuntimeException("expected IllegalArgumentException");
    } catch (IllegalArgumentException expected) {
    }
  }

  private static void testOwnable() {
    Ownable ownable = new Ownable(ALICE);
    IERC5313 standardOwner = ownable;
    expect(standardOwner.owner().equals(ALICE));
    expect(ownable instanceof IERC5313);
    ownable.transferOwnership(ALICE, BOB);
    expect(standardOwner.owner().equals(BOB));

    expectRevert(Ownable.UNAUTHORIZED, new Action() {
      public void run() {
        ownable.transferOwnership(ALICE, CAROL);
      }
    });

    expectRevert(Ownable.INVALID_OWNER, new Action() {
      public void run() {
        new Ownable(Address.ZERO);
      }
    });

    Ownable2Step twoStep = new Ownable2Step(ALICE);
    IERC5313 twoStepOwner = twoStep;
    twoStep.transferOwnership(ALICE, BOB);
    expect(twoStepOwner.owner().equals(ALICE));
    expect(twoStep.pendingOwner().equals(BOB));

    expectRevert(Ownable.UNAUTHORIZED, new Action() {
      public void run() {
        twoStep.acceptOwnership(CAROL);
      }
    });

    twoStep.acceptOwnership(BOB);
    expect(twoStepOwner.owner().equals(BOB));
    expect(! twoStep.hasPendingOwner());
  }

  private static void testAccessControl() {
    TestAccessControl access = new TestAccessControl(ALICE);
    expect(access.supportsInterface(IERC165.INTERFACE_ID));
    expect(access.supportsInterface(IAccessControl.INTERFACE_ID));
    expect(! access.supportsInterface(IERC20.INTERFACE_ID));

    IAccessControl typedAccess = access;
    expect(typedAccess.hasRole(AccessControl.DEFAULT_ADMIN_ROLE, ALICE));
    expect(access.hasRole(AccessControl.DEFAULT_ADMIN_ROLE, ALICE));

    typedAccess.grantRole(ALICE, MINTER_ROLE, BOB);
    expect(typedAccess.hasRole(MINTER_ROLE, BOB));

    expectRevert(AccessControl.UNAUTHORIZED, new Action() {
      public void run() {
        typedAccess.grantRole(BOB, MINTER_ROLE, CAROL);
      }
    });

    typedAccess.revokeRole(ALICE, MINTER_ROLE, BOB);
    expect(! typedAccess.hasRole(MINTER_ROLE, BOB));

    typedAccess.grantRole(ALICE, MINTER_ROLE, BOB);
    typedAccess.renounceRole(BOB, MINTER_ROLE, BOB);
    expect(! typedAccess.hasRole(MINTER_ROLE, BOB));

    expectRevert(AccessControl.BAD_CONFIRMATION, new Action() {
      public void run() {
        typedAccess.renounceRole(ALICE, AccessControl.DEFAULT_ADMIN_ROLE, BOB);
      }
    });
  }

  private static void testPauseAndReentrancy() {
    Pausable pausable = new Pausable();
    expect(! pausable.paused());
    pausable.pause(ALICE);
    expect(pausable.paused());
    expectRevert(Pausable.ENFORCED_PAUSE, new Action() {
      public void run() {
        pausable.requireNotPaused();
      }
    });
    pausable.unpause(ALICE);
    expect(! pausable.paused());
    expectRevert(Pausable.EXPECTED_PAUSE, new Action() {
      public void run() {
        pausable.requirePaused();
      }
    });

    ReentrancyGuard guard = new ReentrancyGuard();
    guard.enter();
    expect(guard.entered());
    expectRevert(ReentrancyGuard.REENTRANT_CALL, new Action() {
      public void run() {
        guard.enter();
      }
    });
    guard.exit();
    expect(! guard.entered());
  }

  private static void testNonces() {
    Nonces nonces = new Nonces();
    expect(nonces.nonce(ALICE).equals(Uint256.ZERO));
    expect(nonces.useNonce(ALICE).equals(Uint256.ZERO));
    expect(nonces.nonce(ALICE).equals(Uint256.ONE));
    nonces.requireNonce(ALICE, Uint256.ONE);
    expectRevert("InvalidAccountNonce(address,uint256)", new Action() {
      public void run() {
        nonces.requireNonce(ALICE, Uint256.ZERO);
      }
    });
  }

  private static void testERC20() {
    TestToken token = new TestToken("Token", "TOK");
    IERC20Metadata metadata = token;
    expect(metadata.name().equals("Token"));
    expect(metadata.symbol().equals("TOK"));
    expect(metadata.decimals() == 18);
    expect(token instanceof IERC20);
    expect(token instanceof IERC20Errors);

    token.mintForTest(ALICE, Uint256.valueOf(100));
    IERC20 erc20 = token;
    expect(erc20.totalSupply().equals(Uint256.valueOf(100)));
    expect(erc20.balanceOf(ALICE).equals(Uint256.valueOf(100)));

    erc20.transfer(ALICE, BOB, Uint256.valueOf(25));
    expect(erc20.balanceOf(ALICE).equals(Uint256.valueOf(75)));
    expect(erc20.balanceOf(BOB).equals(Uint256.valueOf(25)));

    erc20.approve(ALICE, CAROL, Uint256.valueOf(40));
    expect(erc20.allowance(ALICE, CAROL).equals(Uint256.valueOf(40)));
    erc20.transferFrom(CAROL, ALICE, BOB, Uint256.valueOf(15));
    expect(erc20.allowance(ALICE, CAROL).equals(Uint256.valueOf(25)));
    expect(erc20.balanceOf(ALICE).equals(Uint256.valueOf(60)));
    expect(erc20.balanceOf(BOB).equals(Uint256.valueOf(40)));

    expectRevert(ERC20.INSUFFICIENT_ALLOWANCE, new Action() {
      public void run() {
        erc20.transferFrom(CAROL, ALICE, BOB, Uint256.valueOf(30));
      }
    });

    expectRevert(ERC20.INSUFFICIENT_BALANCE, new Action() {
      public void run() {
        erc20.transfer(ALICE, BOB, Uint256.valueOf(1000));
      }
    });

    erc20.approve(ALICE, CAROL, Uint256.MAX_VALUE);
    erc20.transferFrom(CAROL, ALICE, BOB, Uint256.valueOf(10));
    expect(erc20.allowance(ALICE, CAROL).equals(Uint256.MAX_VALUE));
  }

  private static void testERC721() {
    TestNFT nft = new TestNFT("Collectible", "NFT");
    IERC721Metadata metadata = nft;
    IERC721 erc721 = nft;

    expect(metadata.name().equals("Collectible"));
    expect(metadata.symbol().equals("NFT"));
    expect(nft.supportsInterface(IERC165.INTERFACE_ID));
    expect(nft.supportsInterface(IERC721.INTERFACE_ID));
    expect(nft.supportsInterface(IERC721Metadata.INTERFACE_ID));
    expect(! nft.supportsInterface(IERC20.INTERFACE_ID));
    expect(nft instanceof IERC721Errors);

    Uint256 tokenOne = Uint256.ONE;
    Uint256 tokenTwo = Uint256.valueOf(2);

    nft.mintForTest(ALICE, tokenOne);
    expect(erc721.balanceOf(ALICE).equals(Uint256.ONE));
    expect(erc721.ownerOf(tokenOne).equals(ALICE));
    expect(erc721.getApproved(tokenOne).equals(Address.ZERO));
    expect(metadata.tokenURI(tokenOne).equals("tos://nft/1"));

    erc721.approve(ALICE, BOB, tokenOne);
    expect(erc721.getApproved(tokenOne).equals(BOB));

    expectRevert(ERC721.INSUFFICIENT_APPROVAL, new Action() {
      public void run() {
        erc721.transferFrom(CAROL, ALICE, BOB, tokenOne);
      }
    });

    erc721.transferFrom(BOB, ALICE, CAROL, tokenOne);
    expect(erc721.ownerOf(tokenOne).equals(CAROL));
    expect(erc721.balanceOf(ALICE).equals(Uint256.ZERO));
    expect(erc721.balanceOf(CAROL).equals(Uint256.ONE));
    expect(erc721.getApproved(tokenOne).equals(Address.ZERO));

    nft.mintForTest(ALICE, tokenTwo);
    erc721.setApprovalForAll(ALICE, BOB, true);
    expect(erc721.isApprovedForAll(ALICE, BOB));
    erc721.safeTransferFrom(BOB, ALICE, CAROL, tokenTwo, Bytes.fromHex("01"));
    expect(erc721.ownerOf(tokenTwo).equals(CAROL));
    erc721.setApprovalForAll(ALICE, BOB, false);
    expect(! erc721.isApprovedForAll(ALICE, BOB));

    expectRevert(ERC721.INCORRECT_OWNER, new Action() {
      public void run() {
        erc721.transferFrom(CAROL, ALICE, BOB, tokenOne);
      }
    });

    expectRevert(ERC721.INVALID_OWNER, new Action() {
      public void run() {
        erc721.balanceOf(Address.ZERO);
      }
    });

    expectRevert(ERC721.NONEXISTENT_TOKEN, new Action() {
      public void run() {
        erc721.ownerOf(Uint256.valueOf(999));
      }
    });

    nft.burnForTest(tokenOne);
    expectRevert(ERC721.NONEXISTENT_TOKEN, new Action() {
      public void run() {
        erc721.ownerOf(tokenOne);
      }
    });
  }

  private static void testERC2981() {
    TestRoyalty standalone = new TestRoyalty();
    IERC2981 royalty = standalone;

    expect(standalone.supportsInterface(IERC165.INTERFACE_ID));
    expect(standalone.supportsInterface(IERC2981.INTERFACE_ID));
    expect(! standalone.supportsInterface(IERC721.INTERFACE_ID));
    expect(standalone instanceof IERC2981Errors);
    expect(standalone.feeDenominatorForTest().equals(Uint256.valueOf(10000)));

    RoyaltyInfo none = royalty.royaltyInfo(Uint256.ONE,
        Uint256.valueOf(10000));
    expect(none.receiver().equals(Address.ZERO));
    expect(none.royaltyAmount().equals(Uint256.ZERO));

    standalone.setDefaultRoyaltyForTest(ALICE, Uint256.valueOf(500));
    RoyaltyInfo defaultRoyalty = royalty.royaltyInfo(Uint256.ONE,
        Uint256.valueOf(10000));
    expect(defaultRoyalty.receiver().equals(ALICE));
    expect(defaultRoyalty.royaltyAmount().equals(Uint256.valueOf(500)));

    standalone.setTokenRoyaltyForTest(Uint256.ONE, BOB,
        Uint256.valueOf(1000));
    RoyaltyInfo tokenRoyalty = royalty.royaltyInfo(Uint256.ONE,
        Uint256.valueOf(10000));
    expect(tokenRoyalty.receiver().equals(BOB));
    expect(tokenRoyalty.royaltyAmount().equals(Uint256.valueOf(1000)));

    RoyaltyInfo defaultForOtherToken = royalty.royaltyInfo(Uint256.valueOf(2),
        Uint256.valueOf(10000));
    expect(defaultForOtherToken.receiver().equals(ALICE));
    expect(defaultForOtherToken.royaltyAmount().equals(Uint256.valueOf(500)));

    standalone.resetTokenRoyaltyForTest(Uint256.ONE);
    expect(royalty.royaltyInfo(Uint256.ONE, Uint256.valueOf(10000))
           .equals(defaultRoyalty));
    standalone.deleteDefaultRoyaltyForTest();
    expect(royalty.royaltyInfo(Uint256.ONE, Uint256.valueOf(10000))
           .equals(new RoyaltyInfo(Address.ZERO, Uint256.ZERO)));

    expectRevert(ERC2981.INVALID_DEFAULT_ROYALTY, new Action() {
      public void run() {
        standalone.setDefaultRoyaltyForTest(ALICE, Uint256.valueOf(10001));
      }
    });

    expectRevert(ERC2981.INVALID_DEFAULT_ROYALTY_RECEIVER, new Action() {
      public void run() {
        standalone.setDefaultRoyaltyForTest(Address.ZERO, Uint256.ONE);
      }
    });

    expectRevert(ERC2981.INVALID_TOKEN_ROYALTY, new Action() {
      public void run() {
        standalone.setTokenRoyaltyForTest(Uint256.ONE, ALICE,
            Uint256.valueOf(10001));
      }
    });

    expectRevert(ERC2981.INVALID_TOKEN_ROYALTY_RECEIVER, new Action() {
      public void run() {
        standalone.setTokenRoyaltyForTest(Uint256.ONE, Address.ZERO,
            Uint256.ONE);
      }
    });

    TestRoyaltyNFT nft = new TestRoyaltyNFT("Royalty NFT", "RNFT");
    IERC721Metadata metadata = nft;
    IERC2981 nftRoyalty = nft;
    expect(metadata.name().equals("Royalty NFT"));
    expect(nft.supportsInterface(IERC721.INTERFACE_ID));
    expect(nft.supportsInterface(IERC721Metadata.INTERFACE_ID));
    expect(nft.supportsInterface(IERC2981.INTERFACE_ID));
    expect(nft instanceof IERC2981Errors);

    nft.mintForTest(ALICE, Uint256.ONE);
    nft.setDefaultRoyaltyForTest(CAROL, Uint256.valueOf(250));
    RoyaltyInfo nftInfo = nftRoyalty.royaltyInfo(Uint256.ONE,
        Uint256.valueOf(20000));
    expect(nftInfo.receiver().equals(CAROL));
    expect(nftInfo.royaltyAmount().equals(Uint256.valueOf(500)));
  }

  private static void testERC1155() {
    TestMultiToken token = new TestMultiToken("tos://multi/{id}.json");
    IERC1155MetadataURI metadata = token;
    IERC1155 erc1155 = token;

    expect(metadata.uri(Uint256.ONE).equals("tos://multi/{id}.json"));
    token.setURIForTest("tos://changed/{id}.json");
    expect(metadata.uri(Uint256.ONE).equals("tos://changed/{id}.json"));
    expect(token.supportsInterface(IERC165.INTERFACE_ID));
    expect(token.supportsInterface(IERC1155.INTERFACE_ID));
    expect(token.supportsInterface(IERC1155MetadataURI.INTERFACE_ID));
    expect(! token.supportsInterface(IERC721.INTERFACE_ID));
    expect(token instanceof IERC1155Errors);

    Uint256 idOne = Uint256.ONE;
    Uint256 idTwo = Uint256.valueOf(2);
    Uint256[] ids = new Uint256[] { idOne, idTwo };

    token.mintForTest(ALICE, idOne, Uint256.valueOf(100));
    token.mintBatchForTest(ALICE, ids,
        new Uint256[] { Uint256.valueOf(7), Uint256.valueOf(11) });
    expect(erc1155.balanceOf(ALICE, idOne).equals(Uint256.valueOf(107)));
    expect(erc1155.balanceOf(ALICE, idTwo).equals(Uint256.valueOf(11)));

    Uint256[] balances = erc1155.balanceOfBatch(
        new Address[] { ALICE, ALICE, BOB },
        new Uint256[] { idOne, idTwo, idOne });
    expect(balances[0].equals(Uint256.valueOf(107)));
    expect(balances[1].equals(Uint256.valueOf(11)));
    expect(balances[2].equals(Uint256.ZERO));

    expectRevert(ERC1155.MISSING_APPROVAL_FOR_ALL, new Action() {
      public void run() {
        erc1155.safeTransferFrom(BOB, ALICE, CAROL, idOne,
            Uint256.ONE, Bytes.EMPTY);
      }
    });

    erc1155.safeTransferFrom(ALICE, ALICE, BOB, idOne,
        Uint256.valueOf(25), Bytes.EMPTY);
    expect(erc1155.balanceOf(ALICE, idOne).equals(Uint256.valueOf(82)));
    expect(erc1155.balanceOf(BOB, idOne).equals(Uint256.valueOf(25)));

    erc1155.setApprovalForAll(ALICE, BOB, true);
    expect(erc1155.isApprovedForAll(ALICE, BOB));
    erc1155.safeBatchTransferFrom(BOB, ALICE, CAROL, ids,
        new Uint256[] { Uint256.valueOf(12), Uint256.valueOf(3) },
        Bytes.fromHex("0102"));
    expect(erc1155.balanceOf(ALICE, idOne).equals(Uint256.valueOf(70)));
    expect(erc1155.balanceOf(ALICE, idTwo).equals(Uint256.valueOf(8)));
    expect(erc1155.balanceOf(CAROL, idOne).equals(Uint256.valueOf(12)));
    expect(erc1155.balanceOf(CAROL, idTwo).equals(Uint256.valueOf(3)));

    erc1155.setApprovalForAll(ALICE, BOB, false);
    expect(! erc1155.isApprovedForAll(ALICE, BOB));

    expectRevert(ERC1155.INVALID_ARRAY_LENGTH, new Action() {
      public void run() {
        erc1155.balanceOfBatch(new Address[] { ALICE }, ids);
      }
    });

    erc1155.setApprovalForAll(ALICE, BOB, true);
    expectRevert(ERC1155.INVALID_ARRAY_LENGTH, new Action() {
      public void run() {
        erc1155.safeBatchTransferFrom(BOB, ALICE, CAROL, ids,
            new Uint256[] { Uint256.ONE }, Bytes.EMPTY);
      }
    });

    expectRevert(ERC1155.INSUFFICIENT_BALANCE, new Action() {
      public void run() {
        erc1155.safeTransferFrom(BOB, ALICE, CAROL, idTwo,
            Uint256.valueOf(1000), Bytes.EMPTY);
      }
    });

    expectRevert(ERC1155.INVALID_RECEIVER, new Action() {
      public void run() {
        erc1155.safeTransferFrom(ALICE, ALICE, Address.ZERO, idOne,
            Uint256.ONE, Bytes.EMPTY);
      }
    });

    expectRevert(ERC1155.INVALID_SENDER, new Action() {
      public void run() {
        erc1155.safeTransferFrom(Address.ZERO, Address.ZERO, ALICE, idOne,
            Uint256.ONE, Bytes.EMPTY);
      }
    });

    expectRevert(ERC1155.INVALID_OPERATOR, new Action() {
      public void run() {
        erc1155.setApprovalForAll(ALICE, Address.ZERO, true);
      }
    });

    token.burnForTest(BOB, idOne, Uint256.valueOf(5));
    expect(erc1155.balanceOf(BOB, idOne).equals(Uint256.valueOf(20)));
    token.burnBatchForTest(CAROL, ids,
        new Uint256[] { Uint256.valueOf(2), Uint256.ONE });
    expect(erc1155.balanceOf(CAROL, idOne).equals(Uint256.valueOf(10)));
    expect(erc1155.balanceOf(CAROL, idTwo).equals(Uint256.valueOf(2)));
  }

  private static void testERC6909() {
    TestMultiAsset token = new TestMultiAsset();
    IERC6909 erc6909 = token;
    IERC6909TokenSupply supply = token;

    expect(token.supportsInterface(IERC165.INTERFACE_ID));
    expect(token.supportsInterface(IERC6909.INTERFACE_ID));
    expect(token.supportsInterface(IERC6909TokenSupply.INTERFACE_ID));
    expect(! token.supportsInterface(IERC1155.INTERFACE_ID));
    expect(token instanceof IERC6909Errors);

    Uint256 idOne = Uint256.ONE;
    Uint256 idTwo = Uint256.valueOf(2);
    token.mintForTest(ALICE, idOne, Uint256.valueOf(100));
    token.mintForTest(ALICE, idTwo, Uint256.valueOf(7));
    expect(erc6909.balanceOf(ALICE, idOne).equals(Uint256.valueOf(100)));
    expect(erc6909.balanceOf(ALICE, idTwo).equals(Uint256.valueOf(7)));
    expect(supply.totalSupply(idOne).equals(Uint256.valueOf(100)));
    expect(supply.totalSupply(idTwo).equals(Uint256.valueOf(7)));

    erc6909.transfer(ALICE, BOB, idOne, Uint256.valueOf(25));
    expect(erc6909.balanceOf(ALICE, idOne).equals(Uint256.valueOf(75)));
    expect(erc6909.balanceOf(BOB, idOne).equals(Uint256.valueOf(25)));

    erc6909.approve(ALICE, CAROL, idOne, Uint256.valueOf(40));
    expect(erc6909.allowance(ALICE, CAROL, idOne)
           .equals(Uint256.valueOf(40)));
    erc6909.transferFrom(CAROL, ALICE, BOB, idOne, Uint256.valueOf(15));
    expect(erc6909.allowance(ALICE, CAROL, idOne)
           .equals(Uint256.valueOf(25)));
    expect(erc6909.balanceOf(ALICE, idOne).equals(Uint256.valueOf(60)));
    expect(erc6909.balanceOf(BOB, idOne).equals(Uint256.valueOf(40)));

    erc6909.setOperator(ALICE, CAROL, true);
    expect(erc6909.isOperator(ALICE, CAROL));
    erc6909.transferFrom(CAROL, ALICE, BOB, idTwo, Uint256.valueOf(3));
    expect(erc6909.balanceOf(ALICE, idTwo).equals(Uint256.valueOf(4)));
    expect(erc6909.balanceOf(BOB, idTwo).equals(Uint256.valueOf(3)));
    erc6909.setOperator(ALICE, CAROL, false);
    expect(! erc6909.isOperator(ALICE, CAROL));

    erc6909.approve(ALICE, CAROL, idOne, Uint256.MAX_VALUE);
    erc6909.transferFrom(CAROL, ALICE, BOB, idOne, Uint256.valueOf(10));
    expect(erc6909.allowance(ALICE, CAROL, idOne)
           .equals(Uint256.MAX_VALUE));

    expectRevert(ERC6909.INSUFFICIENT_ALLOWANCE, new Action() {
      public void run() {
        erc6909.transferFrom(CAROL, ALICE, BOB, idTwo, Uint256.valueOf(2));
      }
    });

    expectRevert(ERC6909.INSUFFICIENT_BALANCE, new Action() {
      public void run() {
        erc6909.transfer(ALICE, BOB, idOne, Uint256.valueOf(1000));
      }
    });

    expectRevert(ERC6909.INVALID_RECEIVER, new Action() {
      public void run() {
        erc6909.transfer(ALICE, Address.ZERO, idOne, Uint256.ONE);
      }
    });

    expectRevert(ERC6909.INVALID_SENDER, new Action() {
      public void run() {
        erc6909.transfer(Address.ZERO, ALICE, idOne, Uint256.ONE);
      }
    });

    expectRevert(ERC6909.INVALID_APPROVER, new Action() {
      public void run() {
        erc6909.approve(Address.ZERO, BOB, idOne, Uint256.ONE);
      }
    });

    expectRevert(ERC6909.INVALID_SPENDER, new Action() {
      public void run() {
        erc6909.setOperator(ALICE, Address.ZERO, true);
      }
    });

    token.burnForTest(BOB, idOne, Uint256.valueOf(5));
    expect(erc6909.balanceOf(BOB, idOne).equals(Uint256.valueOf(45)));
    expect(supply.totalSupply(idOne).equals(Uint256.valueOf(95)));

    TestMultiAssetMetadata metadataToken = new TestMultiAssetMetadata();
    IERC6909Metadata metadata = metadataToken;
    metadataToken.setNameForTest(idOne, "Gold");
    metadataToken.setSymbolForTest(idOne, "GLD");
    metadataToken.setDecimalsForTest(idOne, 6);
    expect(metadataToken.supportsInterface(IERC6909Metadata.INTERFACE_ID));
    expect(metadata.name(idOne).equals("Gold"));
    expect(metadata.symbol(idOne).equals("GLD"));
    expect(metadata.decimals(idOne) == 6);
    expect(metadata.name(idTwo).equals(""));
    expect(metadata.symbol(idTwo).equals(""));
    expect(metadata.decimals(idTwo) == 0);

    expectIllegalArgument(new Action() {
      public void run() {
        metadataToken.setDecimalsForTest(idOne, 256);
      }
    });

    TestMultiAssetContentURI content = new TestMultiAssetContentURI();
    IERC6909ContentURI uris = content;
    content.setContractURIForTest("tos://collection.json");
    content.setTokenURIForTest(idOne, "tos://asset/1.json");
    expect(content.supportsInterface(IERC6909ContentURI.INTERFACE_ID));
    expect(uris.contractURI().equals("tos://collection.json"));
    expect(uris.tokenURI(idOne).equals("tos://asset/1.json"));
    expect(uris.tokenURI(idTwo).equals(""));
  }

  private static void testReceivers() {
    ERC721Holder erc721Holder = new ERC721Holder();
    IERC721Receiver erc721Receiver = erc721Holder;
    expect(erc721Receiver.onERC721Received(ALICE, BOB, Uint256.ONE,
        Bytes.fromHex("01")).equals(IERC721Receiver
            .ON_ERC721_RECEIVED_SELECTOR));

    ERC1155Holder erc1155Holder = new ERC1155Holder();
    IERC1155Receiver erc1155Receiver = erc1155Holder;
    expect(erc1155Holder.supportsInterface(IERC165.INTERFACE_ID));
    expect(erc1155Holder.supportsInterface(IERC1155Receiver.INTERFACE_ID));
    expect(! erc1155Holder.supportsInterface(IERC1155.INTERFACE_ID));
    expect(erc1155Receiver.onERC1155Received(ALICE, BOB, Uint256.ONE,
        Uint256.valueOf(2), Bytes.EMPTY).equals(IERC1155Receiver
            .ON_ERC1155_RECEIVED_SELECTOR));
    expect(erc1155Receiver.onERC1155BatchReceived(ALICE, BOB,
        new Uint256[] { Uint256.ONE }, new Uint256[] { Uint256.valueOf(2) },
        Bytes.EMPTY).equals(IERC1155Receiver
            .ON_ERC1155_BATCH_RECEIVED_SELECTOR));
  }

  public static void main(String[] args) {
    testOwnable();
    testAccessControl();
    testPauseAndReentrancy();
    testNonces();
    testERC20();
    testERC721();
    testERC2981();
    testERC1155();
    testERC6909();
    testReceivers();
  }

  private static final class TestAccessControl extends AccessControl {
    TestAccessControl(Address admin) {
      grantRoleInternal(AccessControl.DEFAULT_ADMIN_ROLE, admin);
    }
  }

  private static final class TestToken extends ERC20 {
    TestToken(String name, String symbol) {
      super(name, symbol);
    }

    void mintForTest(Address account, Uint256 value) {
      mint(account, value);
    }
  }

  private static final class TestNFT extends ERC721 {
    TestNFT(String name, String symbol) {
      super(name, symbol);
    }

    protected String baseURI() {
      return "tos://nft/";
    }

    void mintForTest(Address account, Uint256 tokenId) {
      mint(account, tokenId);
    }

    void burnForTest(Uint256 tokenId) {
      burn(tokenId);
    }
  }

  private static final class TestRoyalty extends ERC2981 {
    Uint256 feeDenominatorForTest() {
      return feeDenominator();
    }

    void setDefaultRoyaltyForTest(Address receiver, Uint256 feeNumerator) {
      setDefaultRoyalty(receiver, feeNumerator);
    }

    void deleteDefaultRoyaltyForTest() {
      deleteDefaultRoyalty();
    }

    void setTokenRoyaltyForTest(Uint256 tokenId, Address receiver,
                                Uint256 feeNumerator) {
      setTokenRoyalty(tokenId, receiver, feeNumerator);
    }

    void resetTokenRoyaltyForTest(Uint256 tokenId) {
      resetTokenRoyalty(tokenId);
    }
  }

  private static final class TestRoyaltyNFT extends ERC721Royalty {
    TestRoyaltyNFT(String name, String symbol) {
      super(name, symbol);
    }

    void mintForTest(Address account, Uint256 tokenId) {
      mint(account, tokenId);
    }

    void setDefaultRoyaltyForTest(Address receiver, Uint256 feeNumerator) {
      setDefaultRoyalty(receiver, feeNumerator);
    }
  }

  private static final class TestMultiToken extends ERC1155 {
    TestMultiToken(String uri) {
      super(uri);
    }

    void setURIForTest(String uri) {
      setURI(uri);
    }

    void mintForTest(Address account, Uint256 id, Uint256 value) {
      mint(account, id, value);
    }

    void mintBatchForTest(Address account, Uint256[] ids, Uint256[] values) {
      mintBatch(account, ids, values);
    }

    void burnForTest(Address account, Uint256 id, Uint256 value) {
      burn(account, id, value);
    }

    void burnBatchForTest(Address account, Uint256[] ids, Uint256[] values) {
      burnBatch(account, ids, values);
    }
  }

  private static final class TestMultiAsset extends ERC6909TokenSupply {
    void mintForTest(Address account, Uint256 id, Uint256 amount) {
      mint(account, id, amount);
    }

    void burnForTest(Address account, Uint256 id, Uint256 amount) {
      burn(account, id, amount);
    }
  }

  private static final class TestMultiAssetMetadata extends ERC6909Metadata {
    void setNameForTest(Uint256 id, String name) {
      setName(id, name);
    }

    void setSymbolForTest(Uint256 id, String symbol) {
      setSymbol(id, symbol);
    }

    void setDecimalsForTest(Uint256 id, int decimals) {
      setDecimals(id, decimals);
    }
  }

  private static final class TestMultiAssetContentURI
    extends ERC6909ContentURI
  {
    void setContractURIForTest(String uri) {
      setContractURI(uri);
    }

    void setTokenURIForTest(Uint256 id, String uri) {
      setTokenURI(id, uri);
    }
  }
}
