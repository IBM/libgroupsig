const group = (sequelize, DataTypes) => {
    const Group = sequelize.define('group', {
    code: {
      type: DataTypes.INTEGER,
      unique: false,
      allowNull: false,
      validate: {
        notEmpty: true,
      },
    },	
    grpkey: {
      type: DataTypes.TEXT,
      unique: true,
      allowNull: false,
      validate: {
        notEmpty: true,
      },
    },
    mgrkey: {
      type: DataTypes.TEXT,
      unique: true,
      allowNull: false,
      validate: {
        notEmpty: true,
      },
    },      
  });

  Group.associate = models => {
    Group.hasMany(models.Member, { onDelete: 'CASCADE' });
  };

  Group.findByGroupKey = async grpkey => {
    let group = await Group.findOne({
      where: { grpkey: grpkey },
    });
 
    return group;
  };    
 
  return Group;
};
 
export default group;
