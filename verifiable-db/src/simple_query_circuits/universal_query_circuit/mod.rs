/// Component implementing the basic operation supported in the universal query circuit, described here
/// https://www.notion.so/lagrangelabs/Queries-Circuits-2695199166a54954bbc44ad9dc398825?pvs=4#46985c2eb90f4af8aa0805a9203e9efa
mod basic_operation;
mod cells;
/// Component binding column values for the given row to the cells tree hash, descibed here
/// https://www.notion.so/lagrangelabs/Queries-Circuits-2695199166a54954bbc44ad9dc398825?pvs=4#9e7230af7b844b4699a078291591b3eb
mod column_extraction;
/// Output component for queries without aggregation operations (i.e., `SUM` or `MIN`) specified in the `SELECT` statement
/// described here: https://www.notion.so/lagrangelabs/Queries-Circuits-2695199166a54954bbc44ad9dc398825?pvs=4#8799521e9e9547aeb61dc306d399d654
mod output_no_aggregation;
/// Output component for queries with aggregation operations (i.e., `SUM` or `MIN`) specified in the `SELECT` statement,
/// described here: https://www.notion.so/lagrangelabs/Queries-Circuits-2695199166a54954bbc44ad9dc398825?pvs=4#3e0a95407a4a474ca8f0fe45b913ea70
mod output_with_aggregation;
/// Universal query circuit, employing several instances of the atomic components found in other modules to process
/// a single row of a table according to a given query. The overall layout of the circuit is described here
/// https://www.notion.so/lagrangelabs/Queries-Circuits-2695199166a54954bbc44ad9dc398825?pvs=4#5c0d5af8c40f4bf0ae7dd13b20a54dcc
/// while the detailed specs can be found here https://www.notion.so/lagrangelabs/Queries-Circuits-2695199166a54954bbc44ad9dc398825?pvs=4#22fbb552e11e411e95d426264c94aa46
mod universal_query_circuit;