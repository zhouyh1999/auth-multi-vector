#include "network_simplex_simple.h"
#include "EMD.h"

#include <cstdint>
#include <vector>

extern "C" int gem_emd_solve_v3(
    int rows,
    int columns,
    const double* supplies,
    const double* demands,
    const double* costs,
    uint64_t max_iterations,
    float* output) {
    if (rows <= 0 || columns <= 0 || supplies == nullptr || demands == nullptr ||
        costs == nullptr || output == nullptr) {
        return 2;
    }
    using namespace lemon;
    using Digraph = FullBipartiteDigraph;
    DIGRAPH_TYPEDEFS(Digraph);
    Digraph graph(rows, columns);
    NetworkSimplexSimple<Digraph, double, double, node_id_type> solver(
        graph,
        true,
        rows + columns,
        static_cast<uint64_t>(rows) * static_cast<uint64_t>(columns),
        max_iterations);
    std::vector<double> signed_demands(static_cast<size_t>(columns));
    for (int column = 0; column < columns; ++column) {
        if (!(demands[column] > 0.0)) {
            return 2;
        }
        signed_demands[static_cast<size_t>(column)] = -demands[column];
    }
    for (int row = 0; row < rows; ++row) {
        if (!(supplies[row] > 0.0)) {
            return 2;
        }
    }
    solver.supplyMap(
        const_cast<double*>(supplies),
        rows,
        signed_demands.data(),
        columns);
    const uint64_t cells =
        static_cast<uint64_t>(rows) * static_cast<uint64_t>(columns);
    for (uint64_t cell = 0; cell < cells; ++cell) {
        solver.setCost(graph.arcFromId(static_cast<int>(cell)), costs[cell]);
    }
    const int status = solver.run();
    if (status != static_cast<int>(solver.OPTIMAL)) {
        return status == static_cast<int>(solver.MAX_ITER_REACHED) ? 1 : 2;
    }
    double total = 0.0;
    Arc arc;
    graph.first(arc);
    for (; arc != INVALID; graph.next(arc)) {
        const int row = graph.source(arc);
        const int column = graph.target(arc) - rows;
        total += solver.flow(arc) * costs[static_cast<size_t>(row) * columns + column];
    }
    *output = static_cast<float>(total);
    return 0;
}

extern "C" int gem_emd_solve_codebook_v3(
    int rows,
    int columns,
    const double* supplies,
    const double* demands,
    const uint32_t* row_codes,
    const uint32_t* column_codes,
    uint32_t fine_count,
    const float* codebook,
    uint64_t max_iterations,
    float* output) {
    if (rows <= 0 || columns <= 0 || supplies == nullptr || demands == nullptr ||
        row_codes == nullptr || column_codes == nullptr || fine_count == 0 ||
        codebook == nullptr || output == nullptr) {
        return 2;
    }
    using namespace lemon;
    using Digraph = FullBipartiteDigraph;
    DIGRAPH_TYPEDEFS(Digraph);
    Digraph graph(rows, columns);
    NetworkSimplexSimple<Digraph, double, double, node_id_type> solver(
        graph,
        true,
        rows + columns,
        static_cast<uint64_t>(rows) * static_cast<uint64_t>(columns),
        max_iterations);
    std::vector<double> signed_demands(static_cast<size_t>(columns));
    for (int column = 0; column < columns; ++column) {
        if (!(demands[column] > 0.0) || column_codes[column] >= fine_count) {
            return 2;
        }
        signed_demands[static_cast<size_t>(column)] = -demands[column];
    }
    for (int row = 0; row < rows; ++row) {
        if (!(supplies[row] > 0.0) || row_codes[row] >= fine_count) {
            return 2;
        }
    }
    solver.supplyMap(
        const_cast<double*>(supplies),
        rows,
        signed_demands.data(),
        columns);
    uint64_t cell = 0;
    for (int row = 0; row < rows; ++row) {
        const uint64_t row_start =
            static_cast<uint64_t>(row_codes[row]) * fine_count;
        for (int column = 0; column < columns; ++column, ++cell) {
            const uint64_t position = row_start + column_codes[column];
            solver.setCost(
                graph.arcFromId(static_cast<int>(cell)),
                static_cast<double>(codebook[position]));
        }
    }
    const int status = solver.run();
    if (status != static_cast<int>(solver.OPTIMAL)) {
        return status == static_cast<int>(solver.MAX_ITER_REACHED) ? 1 : 2;
    }
    double total = 0.0;
    Arc arc;
    graph.first(arc);
    for (; arc != INVALID; graph.next(arc)) {
        const int row = graph.source(arc);
        const int column = graph.target(arc) - rows;
        const uint64_t position =
            static_cast<uint64_t>(row_codes[row]) * fine_count + column_codes[column];
        total += solver.flow(arc) * static_cast<double>(codebook[position]);
    }
    *output = static_cast<float>(total);
    return 0;
}
