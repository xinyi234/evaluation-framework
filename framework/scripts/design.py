#!/usr/bin/env python3
"""Deterministic allocation helpers for the S2 blocked balanced design."""

import hashlib


DESIGN_TYPE = "blocked_balanced_v2"
ALLOCATION_ALGORITHM = "sha256_permuted_cyclic_bibd_v1"
SCHEDULE_ALGORITHM = "sha256_sort_v1"


def stable_digest(seed, *parts):
    material = "|".join([str(seed), *(str(part) for part in parts)])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def ordered_cells(design, claim_id):
    allocation = design["allocation"]
    seed = allocation["seed"]
    cells = [
        (location, method)
        for location in design["locations"]
        for method in design["methods"]
    ]
    return sorted(
        cells,
        key=lambda cell: stable_digest(
            seed, "cell-order", claim_id, cell[0], cell[1]
        )
    )


def allocation_position(design, project_index, agent_index, repeat_index, repeat_count):
    cell_count = len(design["locations"]) * len(design["methods"])
    return (
        (project_index + agent_index) * repeat_count + repeat_index
    ) % cell_count


def assigned_cell(
    design,
    claim_id,
    project_index,
    agent_index,
    repeat_index,
    repeat_count
):
    cells = ordered_cells(design, claim_id)
    position = allocation_position(
        design,
        project_index,
        agent_index,
        repeat_index,
        repeat_count
    )
    location, method = cells[position]
    return {
        "location": location,
        "method": method,
        "allocation_position": position,
        "cell_order_hash": stable_digest(
            design["allocation"]["seed"],
            "ordered-cells",
            claim_id,
            *(f"{loc}/{meth}" for loc, meth in cells)
        )
    }


def schedule_key(design, run_id):
    schedule = design["execution_schedule"]
    return stable_digest(schedule["seed"], "execution", run_id)


def numeric_rank(matrix, tolerance=1e-10):
    """Return a dependency-free floating-point row-reduction rank."""
    if not matrix:
        return 0
    work = [list(map(float, row)) for row in matrix]
    row_count = len(work)
    column_count = len(work[0])
    if any(len(row) != column_count for row in work):
        raise ValueError("matrix rows have inconsistent widths")

    rank = 0
    for column in range(column_count):
        pivot = max(
            range(rank, row_count),
            key=lambda row: abs(work[row][column]),
            default=None
        )
        if pivot is None or abs(work[pivot][column]) <= tolerance:
            continue
        work[rank], work[pivot] = work[pivot], work[rank]
        pivot_value = work[rank][column]
        work[rank] = [value / pivot_value for value in work[rank]]
        for row in range(row_count):
            if row == rank:
                continue
            factor = work[row][column]
            if abs(factor) <= tolerance:
                continue
            work[row] = [
                value - factor * pivot_value
                for value, pivot_value in zip(work[row], work[rank])
            ]
        rank += 1
        if rank == row_count:
            break
    return rank
