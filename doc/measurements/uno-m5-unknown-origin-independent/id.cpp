#include "td/utils/tests.h"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "vm/boc.h"
#include "td/utils/filesystem.h"
#include <iostream>
TEST(BReview, PredecessorIdentity) {
 auto bytes=td::read_file_str("/tmp/uno-m3-live-v909pwpk/debit-authenticated-block.boc").move_as_ok();auto root=vm::std_boc_deserialize(bytes).move_as_ok();
 block::gen::Block::Record block;block::gen::BlockInfo::Record info;CHECK(tlb::unpack_cell(root,block));CHECK(tlb::unpack_cell(block.info,info));
 std::cout<<"PREDECESSOR seqno="<<info.seq_no<<" root="<<root->get_hash().to_hex()<<"\n";
}
