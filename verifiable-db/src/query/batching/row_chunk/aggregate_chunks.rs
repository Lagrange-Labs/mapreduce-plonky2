use mp2_common::{types::CBuilder, u256::UInt256Target, utils::FromTargets};
use plonky2::iop::target::{BoolTarget, Target};

use crate::query::universal_circuit::universal_query_gadget::{OutputValuesTarget, UniversalQueryOutputWires};

use super::{consecutive_rows::are_consecutive_rows, RowChunkData};


pub(crate) fn aggregate_chunks<const MAX_NUM_RESULTS: usize>(
    b: &mut CBuilder,
    first: &RowChunkData<MAX_NUM_RESULTS>,
    second: &RowChunkData<MAX_NUM_RESULTS>,
    min_primary: &UInt256Target,
    max_primary: &UInt256Target,
    min_secondary: &UInt256Target,
    max_secondary: &UInt256Target,
    ops: &[Target; MAX_NUM_RESULTS],
    is_second_dummy: &BoolTarget
) -> RowChunkData<MAX_NUM_RESULTS> 
where [(); MAX_NUM_RESULTS-1]:,
{
    let _true = b._true();
    // check that right boundary row of chunk1 and left boundary row of chunk2 
	// are consecutive
	let are_consecutive = are_consecutive_rows(
        b,
		&first.right_boundary_row, 
		&second.left_boundary_row,
		min_primary,
        max_primary,
        min_secondary,
        max_secondary
	);
	// assert that the 2 chunks are consecutive only if the second one is not dummy
	let are_consecutive = b.or(are_consecutive, *is_second_dummy);
    b.connect(are_consecutive.target, _true.target);

    // check the same root of the index tree is employed in both chunks to prove 
	// membership of rows in the chunks
    b.connect_hashes(
        first.chunk_outputs.tree_hash, 
        second.chunk_outputs.tree_hash
    );
    // sum the number of matching rows of the 2 chunks
    let count = b.add(first.chunk_outputs.count, second.chunk_outputs.count);

    // aggregate output values. Note that we can aggregate outputs also if chunk2 is
	// dummy, since the universal queyr gadget guarantees that dummy rows output
	// values won't affect the final output values
    let mut output_values = vec![];
    let values = [first.chunk_outputs.values.clone(), second.chunk_outputs.values.clone()];

    let mut num_overflows = b.add(first.chunk_outputs.num_overflows, second.chunk_outputs.num_overflows);
    for i in 0..MAX_NUM_RESULTS {
        let (output, overflows) = OutputValuesTarget::aggregate_outputs(
            b, 
            &values, 
            ops[i], 
            i
        );
        output_values.extend_from_slice(&output);
        num_overflows = b.add(num_overflows, overflows);
    }
    
    RowChunkData {
        left_boundary_row: first.left_boundary_row.clone(),
        right_boundary_row: todo!(),
        chunk_outputs: UniversalQueryOutputWires {
            tree_hash: first.chunk_outputs.tree_hash, //  we check it's the same between the 2 chunks
            values: OutputValuesTarget::from_targets(&output_values),
            count,
            num_overflows,
        },
    }
}