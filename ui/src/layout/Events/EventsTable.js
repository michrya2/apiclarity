import React, { useMemo } from 'react';
import { useHistory, useRouteMatch } from 'react-router-dom';
import Table, { utils } from 'components/Table';
import Tag from 'components/Tag';
import StatusIndicator from 'components/StatusIndicator';
import SpecDiffIcon, { SPEC_DIFF_TYPES_MAP } from 'components/SpecDiffIcon';
import BflaStatusIcon, { BFLA_STATUS_TYPES_MAP } from 'components/BflaStatusIcon';
import { formatDate } from 'utils/utils';
import { API_TYPE_ITEMS } from 'layout/Inventory';

const EventsTable = ({filters, refreshTimestamp}) => {
    const columns = useMemo(() => [
        {
            Header: 'Time',
            id: "time",
            accessor: original => formatDate(original.time),
            width: 70
        },
        {
            Header: 'Method',
            id: "method",
            Cell: ({row}) => {
                const {method} = row.original;

                return (
                    <Tag>{method}</Tag>
                )
            },
            canSort: true,
            width: 40
        },
        {
            Header: 'Path',
            id: "path",
            accessor: "path"
        },
        {
            Header: 'Status Code',
            id: "statusCode",
            Cell: ({row}) => {
                const {statusCode} = row.original;

                return (
                    <StatusIndicator title={statusCode} isError={statusCode >= 400} />
                )
            },
            canSort: true,
            width: 40
        },
        {
            Header: 'Source IP',
            id: "sourceIP",
            accessor: "sourceIP",
            width: 50
        },
        {
            Header: 'Source name',
            id: "sourceK8sObject.name",
            accessor: "sourceK8sObject.name",
            width: 50
        },
        {
            Header: 'Destination IP',
            id: "destinationIP",
            accessor: "destinationIP",
            width: 50
        },
        {
            Header: 'Destination name',
            id: "destinationK8sObject.name",
            accessor: "destinationK8sObject.name",
            width: 50
        },
        {
            Header: 'Destination Port',
            id: "destinationPort",
            accessor: "destinationPort",
            width: 55
        },
        {
            Header: 'Spec Diff',
            id: "specDiffType",
            Cell: ({row}) => {
                const {id, specDiffType} = row.original;

                const {value} = SPEC_DIFF_TYPES_MAP[specDiffType] || {};

                if (!value || value === SPEC_DIFF_TYPES_MAP.NO_DIFF.value) {
                    return <utils.EmptyValue />;
                }

                return (
                    <SpecDiffIcon id={id} specDiffType={specDiffType} />
                )
            },
            canSort: true,
            width: 40
        },
        {
            Header: 'Host',
            id: "hostSpecName",
            accessor: "hostSpecName"
        },
        {
            Header: 'Type',
            id: "apiType",
            accessor: original => {
                const typeItem = API_TYPE_ITEMS[original.apiType];

                return !!typeItem ? typeItem.label : null;
            },
            width: 30
        },
        {
            Header: 'BFLA',
            id: "bflaStatus",
            width: 30,
            Cell: ({row}) => {
                const {id, bflaStatus} = row.original;

                const {value} = BFLA_STATUS_TYPES_MAP[bflaStatus] || {};

                if (!value) {
                    return <utils.EmptyValue />;
                }

                return <BflaStatusIcon id={id} bflaStatusType={bflaStatus} />;
            }
        }
    ], []);

    const history = useHistory();
    const {path} = useRouteMatch();

    return (
        <Table
            columns={columns}
            paginationItemsName="APIs"
            url="apiEvents"
            defaultSortBy={[{id: "time", desc: true}]}
            filters={filters}
            onLineClick={({id}) => history.push(`${path}/${id}`)}
            noResultsTitle="API events"
            refreshTimestamp={refreshTimestamp}
        />
    )
}

export default EventsTable;
