#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <queue>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "hnswlib/hnswlib.h"

// This fixture is compiled against a temporary, patched copy of the fixed
// official GEM checkout. Graph insertion, owner and recipient pruning, repair
// primitives, and online qCH traversal below all execute HierarchicalNSW code
// from that copy. The checked-in patch only resolves repository-undefined
// initialization/ties and exposes a read-only traversal trace for this fixture.

namespace {

using Index = hnswlib::HierarchicalNSW<float>;
using Label = hnswlib::labeltype;
using Table = hnswlib::tableint;
using CandidateQueue = std::priority_queue<
    std::pair<float, Table>, std::vector<std::pair<float, Table>>,
    Index::CompareByFirst>;

constexpr std::size_t kLookupWidth = NUM_CLUSTER_CALC;

std::uint32_t bits(float value) {
    std::uint32_t output = 0;
    std::memcpy(&output, &value, sizeof(output));
    return output;
}

void print_bool(bool value) { std::cout << (value ? "true" : "false"); }

template <typename T>
void print_array(const std::vector<T>& values) {
    std::cout << '[';
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i != 0) std::cout << ',';
        std::cout << values[i];
    }
    std::cout << ']';
}

template <typename T>
void print_graph(const std::vector<std::vector<T>>& graph) {
    std::cout << '[';
    for (std::size_t i = 0; i < graph.size(); ++i) {
        if (i != 0) std::cout << ',';
        print_array(graph[i]);
    }
    std::cout << ']';
}

struct Documents {
    std::vector<std::vector<float>> coordinates;
    std::vector<std::vector<int>> codes;
    std::vector<vectorset> views;

    explicit Documents(std::size_t count) : coordinates(count), codes(count) {
        views.reserve(count);
        for (std::size_t doc = 0; doc < count; ++doc) {
            coordinates[doc] = {1.0F};
            codes[doc] = {static_cast<int>(doc)};
        }
        for (std::size_t doc = 0; doc < count; ++doc) {
            views.emplace_back(coordinates[doc].data(), codes[doc].data(), 1, 1);
        }
    }
};

std::vector<float> similarity_matrix(std::size_t code_count) {
    std::vector<float> similarity(code_count * kLookupWidth, 0.0F);
    for (std::size_t code = 0; code < code_count; ++code) {
        similarity[code * kLookupWidth + code] = 1.0F;
    }
    return similarity;
}

std::vector<float> non_composable_similarity() {
    constexpr std::size_t count = 26;
    std::vector<float> costs(count * count, 2.0F);
    for (std::size_t code = 0; code < count; ++code) {
        costs[code * count + code] = 0.0F;
    }
    const auto set_cost = [&costs](std::size_t left, std::size_t right,
                                   float cost) {
        costs[left * count + right] = cost;
        costs[right * count + left] = cost;
    };
    set_cost(0, 1, 0.5F);
    set_cost(0, 2, 1.0F);
    set_cost(0, 3, 1.5F);
    set_cost(1, 2, 0.75F);
    set_cost(1, 3, 1.75F);
    set_cost(2, 3, 1.25F);
    for (std::size_t filler = 4; filler < count; ++filler) {
        set_cost(0, filler, 1.9F);
        set_cost(1, filler, 0.0F);
        set_cost(2, filler, 0.0F);
    }
    std::vector<float> similarity(count * kLookupWidth, 0.0F);
    for (std::size_t row = 0; row < count; ++row) {
        for (std::size_t column = 0; column < count; ++column) {
            similarity[row * kLookupWidth + column] =
                1.0F - costs[row * count + column];
        }
    }
    return similarity;
}

std::vector<Label> row(const Index& index, Label label) {
    const auto found = index.label_lookup_.find(label);
    if (found == index.label_lookup_.end()) return {};
    const Table internal = found->second;
    hnswlib::linklistsizeint* links = index.get_linklist0(internal);
    const std::size_t count = index.getListCount(links);
    const Table* data = reinterpret_cast<const Table*>(links + 1);
    std::vector<Label> output;
    output.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        output.push_back(index.getExternalLabel(data[i]));
    }
    std::sort(output.begin(), output.end());
    return output;
}

std::vector<std::vector<Label>> graph(const Index& index,
                                      std::size_t document_count) {
    std::vector<std::vector<Label>> output;
    output.reserve(document_count);
    for (std::size_t label = 0; label < document_count; ++label) {
        output.push_back(row(index, label));
    }
    return output;
}

void add_blank_documents(Index& index, Documents& documents,
                         const std::vector<float>& similarity) {
    for (std::size_t label = 0; label < documents.views.size(); ++label) {
        index.addClusterPointEntry(&documents.views[label], similarity.data(), label,
                                   label);
    }
}

void add_directed_edge(Index& index, Label owner, Label neighbor) {
    index.mutuallyConnectTwoInterElement(index.label_lookup_.at(owner),
                                         index.label_lookup_.at(neighbor));
}

CandidateQueue candidates(const Index& index,
                          const std::vector<std::pair<float, Label>>& rows) {
    CandidateQueue output;
    for (const auto& candidate : rows) {
        output.emplace(candidate.first, index.label_lookup_.at(candidate.second));
    }
    return output;
}

struct GraphFixture {
    std::vector<std::vector<Label>> after_entry;
    std::vector<std::vector<Label>> after_insert;
    std::vector<std::uint32_t> qch_bits;
    std::vector<Label> visited;
    std::vector<Label> expanded;
    std::vector<Label> result_ids;
    std::vector<std::uint32_t> result_bits;
};

GraphFixture two_document_graph_and_query() {
    Documents documents(2);
    std::vector<float> similarity = similarity_matrix(2);
    hnswlib::L2VSSpace space(1);
    Index index(&space, 3, 24, 80, 100);

    index.addClusterPointEntry(&documents.views[1], similarity.data(), 1, 1);
    const auto after_entry = graph(index, 2);
    index.addClusterPointEntry(&documents.views[0], similarity.data(), 0, 1);
    const auto after_insert = graph(index, 2);

    std::vector<float> lookup(kLookupWidth, 0.0F);
    lookup[0] = 1.0F;
    lookup[1] = 0.0F;
    vectorset query(lookup.data(), nullptr, static_cast<int>(kLookupWidth), 1);
    index.search_set.assign(index.max_elements_, false);
    for (std::size_t i = 0; i < 2; ++i) {
        index.search_set[index.label_lookup_.at(i)] = true;
    }
    index.setEf(2);
    auto result = index.searchKnnClusterEntries(&query, 2, std::vector<Label>{1});
    std::vector<std::pair<float, Label>> canonical;
    while (!result.empty()) {
        canonical.push_back(result.top());
        result.pop();
    }
    std::sort(canonical.begin(), canonical.end(), [](const auto& left,
                                                     const auto& right) {
        if (left.first != right.first) return left.first < right.first;
        return left.second < right.second;
    });
    std::vector<Label> result_ids;
    std::vector<std::uint32_t> result_bits;
    for (const auto& result_row : canonical) {
        result_ids.push_back(result_row.second);
        result_bits.push_back(bits(result_row.first));
    }
    std::vector<std::uint32_t> qch_bits;
    for (Label label : {Label{0}, Label{1}}) {
        const auto internal = index.label_lookup_.at(label);
        const float distance = index.fstdistfuncCluster(
            &query, reinterpret_cast<const vectorset*>(index.getDataByInternalId(internal)), 0);
        qch_bits.push_back(bits(distance));
    }
    return GraphFixture{after_entry,
                        after_insert,
                        qch_bits,
                        index.fixture_trace_visited,
                        index.fixture_trace_expanded,
                        result_ids,
                        result_bits};
}

std::vector<Label> owner_union_fixture() {
    Documents documents(26);
    std::vector<float> similarity = non_composable_similarity();
    hnswlib::L2VSSpace space(1);
    Index index(&space, 27, 24, 80, 100);
    add_blank_documents(index, documents, similarity);
    add_directed_edge(index, 0, 1);
    std::vector<std::pair<float, Label>> candidate_rows{{1.0F, 2}, {1.5F, 3}};
    for (Label filler = 4; filler < 26; ++filler) {
        candidate_rows.emplace_back(1.9F, filler);
    }
    auto queue = candidates(index, candidate_rows);
    index.mutuallyConnectUpdateElementCluster(
        &documents.views[0], similarity.data(), index.label_lookup_.at(0), queue, 0,
        true);
    return row(index, 0);
}

std::vector<Label> owner_cap_fixture() {
    Documents documents(26);
    std::vector<float> similarity = similarity_matrix(26);
    hnswlib::L2VSSpace space(1);
    Index index(&space, 27, 24, 80, 100);
    add_blank_documents(index, documents, similarity);
    std::vector<std::pair<float, Label>> candidate_rows;
    for (Label candidate = 1; candidate < 26; ++candidate) {
        candidate_rows.emplace_back(1.0F, candidate);
    }
    auto queue = candidates(index, candidate_rows);
    index.mutuallyConnectNewElementCluster(
        &documents.views[0], similarity.data(), index.label_lookup_.at(0), queue, 0,
        true);
    return row(index, 0);
}

std::pair<std::vector<Label>, std::vector<Label>> stale_reciprocal_fixture() {
    Documents documents(26);
    std::vector<float> similarity = non_composable_similarity();
    hnswlib::L2VSSpace space(1);
    Index index(&space, 27, 24, 80, 100);
    add_blank_documents(index, documents, similarity);
    add_directed_edge(index, 0, 2);
    add_directed_edge(index, 2, 0);
    std::vector<std::pair<float, Label>> candidate_rows{{0.5F, 1}, {1.5F, 3}};
    for (Label filler = 4; filler < 26; ++filler) {
        candidate_rows.emplace_back(1.9F, filler);
    }
    auto queue = candidates(index, candidate_rows);
    index.mutuallyConnectUpdateElementCluster(
        &documents.views[0], similarity.data(), index.label_lookup_.at(0), queue, 0,
        true);
    return {row(index, 0), row(index, 2)};
}

std::vector<Label> recipient_49_fixture() {
    Documents documents(50);
    std::vector<float> similarity = similarity_matrix(50);
    hnswlib::L2VSSpace space(1);
    Index index(&space, 51, 24, 80, 100);
    add_blank_documents(index, documents, similarity);
    for (Label neighbor = 1; neighbor <= 48; ++neighbor) {
        add_directed_edge(index, 0, neighbor);
    }
    auto queue = candidates(index, {{1.0F, 0}});
    index.mutuallyConnectNewElementCluster(
        &documents.views[49], similarity.data(), index.label_lookup_.at(49), queue,
        0, true);
    return row(index, 0);
}

struct RepairFixture {
    bool capacity_exhausted;
    std::vector<Label> entry_component;
    std::vector<Label> unbridged_component;
    std::vector<Label> entry_row;
    std::vector<Label> unreachable_row;
};

RepairFixture strict_repair_fixture() {
    Documents documents(51);
    std::vector<float> similarity = similarity_matrix(51);
    hnswlib::L2VSSpace space(1);
    Index index(&space, 52, 24, 80, 100);
    add_blank_documents(index, documents, similarity);
    for (Label neighbor = 0; neighbor < 48; ++neighbor) {
        add_directed_edge(index, 50, neighbor);
    }
    index.entry_map.clear();
    index.entry_map[index.label_lookup_.at(50)] = 0;
    index.entry_map[index.label_lookup_.at(49)] = 0;
    auto reached = index.searchNodesForFix(50, 0);
    std::vector<Label> entry_component;
    for (const auto& reached_row : reached) {
        entry_component.push_back(index.getExternalLabel(reached_row.first));
    }
    std::size_t cursor = 0;
    while (cursor < reached.size() &&
           !index.canAddEdgeinter(reached[cursor].first)) {
        ++cursor;
    }
    const bool exhausted = cursor == reached.size();
    if (!exhausted) {
        index.mutuallyConnectTwoInterElement(reached[cursor].first,
                                             index.label_lookup_.at(49));
    }
    auto component = index.searchNodesForFix(49, 0);
    std::vector<Label> unbridged;
    for (const auto& component_row : component) {
        unbridged.push_back(index.getExternalLabel(component_row.first));
    }
    return RepairFixture{exhausted, entry_component, unbridged, row(index, 50),
                         row(index, 49)};
}

}  // namespace

// Actual upstream traversal at the boundaries that the two-document fixture
// cannot exercise. The patch changes no admission or heap-trimming rules.
void print_query_boundary(const char* name, const std::vector<float>& fine,
                          const std::vector<std::uint32_t>& mapping,
                          const std::vector<float>& coarse,
                          const std::vector<std::vector<Label>>& rows,
                          const std::vector<Label>& entries, std::size_t top_t) {
    Documents documents(fine.size());
    auto similarity = similarity_matrix(fine.size());
    hnswlib::L2VSSpace space(1);
    hnswlib::HierarchicalNSW<float> index(&space, fine.size() + 1, 24, 80, 100);
    add_blank_documents(index, documents, similarity);
    for (Label owner = 0; owner < rows.size(); ++owner)
        for (Label neighbor : rows[owner]) add_directed_edge(index, owner, neighbor);
    std::vector<float> lookup(kLookupWidth, 0.0F);
    std::copy(fine.begin(), fine.end(), lookup.begin());
    vectorset query(lookup.data(), nullptr, static_cast<int>(kLookupWidth), 1);
    index.search_set.assign(index.max_elements_, true);
    index.setEf(2);
    auto heap = index.searchKnnClusterEntries(&query, 2, entries);
    std::vector<std::pair<float, Label>> results;
    while (!heap.empty()) { results.push_back(heap.top()); heap.pop(); }
    std::sort(results.begin(), results.end());
    std::vector<Label> retained;
    std::vector<std::uint32_t> distances;
    for (const auto& result : results) {
        retained.push_back(result.second);
        distances.push_back(bits(result.first));
    }
    std::cout << "{\"name\":\"" << name << "\",\"fine\":"; print_array(fine);
    std::cout << ",\"mapping\":"; print_array(mapping);
    std::cout << ",\"coarse\":"; print_array(coarse);
    std::cout << ",\"adjacency\":"; print_graph(rows);
    std::cout << ",\"cluster_top_t\":" << top_t;
    std::cout << ",\"visited\":"; print_array(index.fixture_trace_visited);
    std::cout << ",\"expanded\":"; print_array(index.fixture_trace_expanded);
    std::cout << ",\"retained\":"; print_array(retained);
    std::cout << ",\"distance_bits\":"; print_array(distances);
    std::cout << '}';
}

void print_construction_score_boundary() {
 Documents documents(82);
 for (size_t i=0;i<82;++i) documents.codes[i][0]=(i==0 ? 2 : (i==1||i==81 ? 1 : 0));
 const float centroids[3]={1.0F,0.0F,0.5F};
 std::vector<float> similarity(3*kLookupWidth,0.0F);
 for(int i=0;i<3;i++)for(int j=0;j<3;j++)similarity[i*kLookupWidth+j]=centroids[i]*centroids[j];
 hnswlib::L2VSSpace space(1); hnswlib::HierarchicalNSW<float> index(&space,83,24,80,100);
 add_blank_documents(index,documents,similarity);
 for(Label j=2;j<=49;j++)add_directed_edge(index,81,j);
 for(Label j=50;j<=80;j++)add_directed_edge(index,2,j);
 add_directed_edge(index,80,1);
 auto heap=index.searchBaseLayerClusterConsPara<true>(index.label_lookup_.at(81),&documents.views[0],similarity.data(),80);
 auto copy=heap; std::vector<Label> ids;
 while(!copy.empty()){ids.push_back(index.getExternalLabel(copy.top().second));copy.pop();}
 std::sort(ids.begin(),ids.end());
 index.mutuallyConnectNewElementCluster(&documents.views[0],similarity.data(),index.label_lookup_.at(0),heap,0,false);
 const auto owner_row=row(index,0);
 std::cout<<"{\"document_count\":82,\"ef_construction\":80,\"candidate_ids\":";print_array(ids);
 std::cout<<",\"owner_row\":";print_array(owner_row);std::cout<<"}";
}

void print_qch_multitoken_boundary(){
 Documents docs(2);auto similarity=similarity_matrix(2);hnswlib::L2VSSpace space(4);hnswlib::HierarchicalNSW<float> index(&space,3,24,80,100);
 add_blank_documents(index,docs,similarity);add_directed_edge(index,1,0);
 const float a[2]={0.244140625F,0.24560546875F},b[2]={0.23974609375F,0.24951171875F};
 std::vector<float> lookup(2*kLookupWidth,0.0F);lookup[0]=0.8F*a[0];lookup[1]=0.9F*a[1];lookup[2]=0.8F*b[0];lookup[3]=0.9F*b[1];
 vectorset query(lookup.data(),nullptr,kLookupWidth,2);index.search_set.assign(index.max_elements_,true);index.setEf(2);
 std::vector<uint32_t> scores;for(int i=0;i<2;i++)scores.push_back(bits(index.fstdistfuncCluster(&query,&docs.views[i],0)));
 auto heap=index.searchKnnClusterEntries(&query,2,std::vector<Label>{1});std::vector<std::pair<float,Label>> result;
 while(!heap.empty()){result.push_back(heap.top());heap.pop();}std::sort(result.begin(),result.end());
 std::cout<<"{\"qch_bits\":";print_array(scores);std::cout<<",\"rerank_k\":1,\"candidate_id\":"<<result.front().second<<"}";
}

int main() {
    const std::vector<std::vector<std::uint32_t>> codes{{0}, {1}};
    const std::vector<std::uint32_t> fine_to_coarse{0, 0};
    const std::size_t document_count = codes.size();
    std::vector<std::uint64_t> document_frequency(1, 0);
    std::vector<std::map<std::uint32_t, std::uint32_t>> counts(document_count);
    for (std::size_t doc = 0; doc < document_count; ++doc) {
        for (std::uint32_t code : codes[doc]) {
            ++counts[doc][fine_to_coarse[code]];
        }
        for (const auto& count : counts[doc]) ++document_frequency[count.first];
    }
    std::vector<std::vector<std::uint32_t>> memberships(document_count);
    std::vector<std::vector<std::uint32_t>> postings(1);
    for (std::size_t doc = 0; doc < document_count; ++doc) {
        std::vector<std::pair<std::uint32_t, double>> scored;
        for (const auto& count : counts[doc]) {
            const double tf = static_cast<double>(count.second) /
                              static_cast<double>(codes[doc].size());
            const double idf = std::log(static_cast<double>(document_count) /
                                        static_cast<double>(document_frequency[count.first]));
            scored.emplace_back(count.first, tf * idf);
        }
        std::sort(scored.begin(), scored.end(), [](const auto& left,
                                                   const auto& right) {
            if (left.second != right.second) return left.second > right.second;
            return left.first < right.first;
        });
        if (scored.size() > 20) scored.resize(20);
        for (const auto& score : scored) {
            memberships[doc].push_back(score.first);
            postings[score.first].push_back(static_cast<std::uint32_t>(doc));
        }
    }
    for (auto& posting : postings) std::reverse(posting.begin(), posting.end());

    const GraphFixture basic = two_document_graph_and_query();
    const std::vector<Label> owner_union = owner_union_fixture();
    const std::vector<Label> owner_cap = owner_cap_fixture();
    const auto stale = stale_reciprocal_fixture();
    const std::vector<Label> recipient = recipient_49_fixture();
    const RepairFixture repair = strict_repair_fixture();

    std::cout << "{\n";
    std::cout << "  \"reference_commit\":\"1b559d0ccb2bea7a23ac9f2f8e84040924e3972f\",\n";
    std::cout << "  \"official_hnsw_calls\":[\"addClusterPointEntry\",\"mutuallyConnectUpdateElementCluster\",\"mutuallyConnectNewElementCluster\",\"searchNodesForFix\",\"canAddEdgeinter\",\"mutuallyConnectTwoInterElement\",\"searchKnnClusterEntries\"],\n";
    std::cout << "  \"memberships\":";
    print_graph(memberships);
    std::cout << ",\n  \"postings\":";
    print_graph(postings);
    std::cout << ",\n  \"graph_steps\":[";
    print_graph(basic.after_entry);
    std::cout << ',';
    print_graph(basic.after_insert);
    std::cout << "],\n  \"owner_single_heuristic_union\":";
    print_array(owner_union);
    std::cout << ",\n  \"owner_cap24_row\":";
    print_array(owner_cap);
    std::cout << ",\n  \"recipient_49_row\":";
    print_array(recipient);
    std::cout << ",\n  \"recipient_49_degree\":" << recipient.size();
    std::cout << ",\n  \"stale_owner_row\":";
    print_array(stale.first);
    std::cout << ",\n  \"stale_reciprocal_row\":";
    print_array(stale.second);
    std::cout << ",\n  \"strict_repair_capacity_exhausted\":";
    print_bool(repair.capacity_exhausted);
    std::cout << ",\n  \"strict_repair_entry_component\":";
    print_array(repair.entry_component);
    std::cout << ",\n  \"strict_repair_unbridged_component\":";
    print_array(repair.unbridged_component);
    std::cout << ",\n  \"strict_repair_entry_row\":";
    print_array(repair.entry_row);
    std::cout << ",\n  \"strict_repair_unreachable_row\":";
    print_array(repair.unreachable_row);
    std::cout << ",\n  \"qch_distance_bits\":";
    print_array(basic.qch_bits);
    std::cout << ",\n  \"selected_clusters\":[0],\n  \"queue_entries\":[[0,1]],\n";
    std::cout << "  \"visited_order\":";
    print_array(basic.visited);
    std::cout << ",\n  \"expanded\":";
    print_array(basic.expanded);
    std::cout << ",\n  \"candidate_ids\":";
    print_array(basic.result_ids);
    std::cout << ",\n  \"candidate_distance_bits\":";
    print_array(basic.result_bits);
    std::cout << ",\n  \"query_boundaries\":[";
    print_query_boundary("equal_score_admission", {1,1,1}, {0,0,0}, {1},
                         {{},{},{0,1}}, {2}, 1);
    std::cout << ',';
    print_query_boundary("entries_above_ef_with_expansion", {1,.25,0,.5,.75},
                         {2,0,2,1,0}, {1,1,1}, {{},{},{0},{},{1}}, {4,3,2}, 3);
    std::cout << ',';
    print_query_boundary("entries_above_ef_without_expansion", {1,.5,0},
                         {0,1,2}, {1,1,1}, {{},{},{}}, {0,1,2}, 3);
    std::cout << ',';
    print_query_boundary("empty_selected_bucket", {1}, {0}, {0,1}, {{}}, {}, 1);
    std::cout << ']';
    std::cout << ",\n  \"construction_score_boundary\":";
    print_construction_score_boundary();
    std::cout << ",\n  \"qch_multitoken_boundary\":";
    print_qch_multitoken_boundary();
    std::cout << "\n}\n";
    return 0;
}
