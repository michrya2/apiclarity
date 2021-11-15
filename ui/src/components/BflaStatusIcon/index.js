import React from 'react';
import Icon, { ICON_NAMES } from 'components/Icon';
import Tooltip from 'components/Tooltip';

import COLORS from 'utils/scss_variables.module.scss';

export const BFLA_STATUS_TYPES_MAP = {
    SUSPICIOUS_SRC_DENIED: {
        value: "SUSPICIOUS_SRC_DENIED",
        label: "Denied",
        icon: ICON_NAMES.ALERT,
        tooltip: "Suspicious Source Denied",
        color: COLORS["color-warning"]
    },
    SUSPICIOUS_SRC_ALLOWED: {
        value: "SUSPICIOUS_SRC_ALLOWED",
        label: "Allowed",
        icon: ICON_NAMES.ALERT,
        tooltip: "Suspicious Source Allowed",
        color: COLORS["color-error"]
    }
};

const BflaStatusIcon = ({id, bflaStatusType}) => {
    const tooltipId = `bfla-status-${id}`;
    const {icon, tooltip, color} = BFLA_STATUS_TYPES_MAP[bflaStatusType] || {};

    return (
        <div className="bfla-status-icon" style={{width: "22px"}}>
            <div data-tip data-for={tooltipId}><Icon name={icon} style={{color}} /></div>
            <Tooltip id={tooltipId} text={tooltip} />
        </div>
    );
};

export default BflaStatusIcon;
