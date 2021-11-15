import React from 'react';
import Filter, { OPERATORS, METHOD_ITEMS, formatFiltersToQueryParams } from 'components/Filter';
import { SPEC_DIFF_TYPES_MAP } from 'components/SpecDiffIcon';
import { BFLA_STATUS_TYPES_MAP } from 'components/BflaStatusIcon';

export {
    formatFiltersToQueryParams
}

const SPEC_DIFF_ITEMS = [
    {value: "true", label: "present"},
    {value: "false", label: "not present"},
];

const FILTERS_MAP = {
    method: {value: "method", label: "Method", valuesMapItems: METHOD_ITEMS, operators: [
        {...OPERATORS.is, valueItems: METHOD_ITEMS, creatable: false}
    ]},
    path: {value: "path", label: "Path", operators: [
        {...OPERATORS.is, valueItems: [], creatable: true},
        {...OPERATORS.isNot, valueItems: [], creatable: true},
        {...OPERATORS.start},
        {...OPERATORS.end},
        {...OPERATORS.contains, valueItems: [], creatable: true}
    ]},
    statusCode: {value: "statusCode", label: "Status code", operators: [
        {...OPERATORS.is, valueItems: [], creatable: true},
        {...OPERATORS.isNot, valueItems: [], creatable: true},
        {...OPERATORS.gte},
        {...OPERATORS.lte},
    ]},
    "sourceK8sObject.name": {value: "sourceK8sObject.name", label: "Source Name", operators: [
        {...OPERATORS.is, valueItems: [], creatable: true},
        {...OPERATORS.isNot, valueItems: [], creatable: true},
        {...OPERATORS.contains, valueItems: [], creatable: true}
    ]},
    sourceIP: {value: "sourceIP", label: "Source IP", operators: [
        {...OPERATORS.is, valueItems: [], creatable: true},
        {...OPERATORS.isNot, valueItems: [], creatable: true}
    ]},
    "destinationK8sObject.name": {value: "destinationK8sObject.name", label: "Destination Name", operators: [
        {...OPERATORS.is, valueItems: [], creatable: true},
        {...OPERATORS.isNot, valueItems: [], creatable: true},
        {...OPERATORS.contains, valueItems: [], creatable: true}
    ]},
    destinationIP: {value: "destinationIP", label: "Destination IP", operators: [
        {...OPERATORS.is, valueItems: [], creatable: true},
        {...OPERATORS.isNot, valueItems: [], creatable: true}
    ]},
    destinationPort: {value: "destinationPort", label: "Destination port", operators: [
        {...OPERATORS.is, valueItems: [], creatable: true},
        {...OPERATORS.isNot, valueItems: [], creatable: true}
    ]},
    spec: {value: "spec", label: "Host", operators: [
        {...OPERATORS.is, valueItems: [], creatable: true},
        {...OPERATORS.isNot, valueItems: [], creatable: true},
        {...OPERATORS.start},
        {...OPERATORS.end},
        {...OPERATORS.contains, valueItems: [], creatable: true}
    ]},
    hasSpecDiff: {value: "hasSpecDiff", label: "Spec diff", valuesMapItems: SPEC_DIFF_ITEMS, operators: [
        {...OPERATORS.is, valueItems: SPEC_DIFF_ITEMS, creatable: false, isSingleSelect: true},
    ]},
    specDiffType: {value: "specDiffType", label: "Spec diff type", operators: [
        {...OPERATORS.is, valueItems: Object.values(SPEC_DIFF_TYPES_MAP), creatable: false}
    ]},
    bflaStatus: {value: "bflaStatus", label: "BFLA", operators: [
        {...OPERATORS.is, valueItems: Object.values(BFLA_STATUS_TYPES_MAP) , creatable: false}
    ]}
};

const GeneralFilter = props => (<Filter {...props} filtersMap={FILTERS_MAP} />);

export default GeneralFilter;
