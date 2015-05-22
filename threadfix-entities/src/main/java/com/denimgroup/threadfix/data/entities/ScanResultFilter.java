package com.denimgroup.threadfix.data.entities;

import javax.persistence.*;
import javax.validation.constraints.NotNull;

@Entity
@Table(name = "ScanResultFilter")
public class ScanResultFilter extends AuditableEntity {

    @NotNull
    private GenericSeverity genericSeverity;

    @NotNull
    private ChannelType channelType;

    @ManyToOne
    @JoinColumn(name = "genericSeverityId")
    public GenericSeverity getGenericSeverity() {
        return genericSeverity;
    }

    public void setGenericSeverity(GenericSeverity genericSeverity) {
        this.genericSeverity = genericSeverity;
    }

    @ManyToOne
    @JoinColumn(name = "channelTypeId")
    public ChannelType getChannelType() {
        return channelType;
    }

    public void setChannelType(ChannelType channelType) {
        this.channelType = channelType;
    }

    @Transient
    public String getScannerTypeName(){
        return this.channelType.getName();
    }
}
