"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _events = require("events");
var _writableTrackingBuffer = _interopRequireDefault(require("./tracking-buffer/writable-tracking-buffer"));
var _stream = require("stream");
var _token = require("./token/token");
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
/**
 * @private
 */
const FLAGS = {
  nullable: 1 << 0,
  caseSen: 1 << 1,
  updateableReadWrite: 1 << 2,
  updateableUnknown: 1 << 3,
  identity: 1 << 4,
  computed: 1 << 5,
  // introduced in TDS 7.2
  fixedLenCLRType: 1 << 8,
  // introduced in TDS 7.2
  sparseColumnSet: 1 << 10,
  // introduced in TDS 7.3.B
  hidden: 1 << 13,
  // introduced in TDS 7.2
  key: 1 << 14,
  // introduced in TDS 7.2
  nullableUnknown: 1 << 15 // introduced in TDS 7.2
};

/**
 * @private
 */
const DONE_STATUS = {
  FINAL: 0x00,
  MORE: 0x1,
  ERROR: 0x2,
  INXACT: 0x4,
  COUNT: 0x10,
  ATTN: 0x20,
  SRVERROR: 0x100
};

/**
 * @private
 */

const rowTokenBuffer = Buffer.from([_token.TYPE.ROW]);
const textPointerAndTimestampBuffer = Buffer.from([
// TextPointer length
0x10,
// TextPointer
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// Timestamp
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
const textPointerNullBuffer = Buffer.from([0x00]);

// A transform that converts rows to packets.
class RowTransform extends _stream.Transform {
  /**
   * @private
   */

  /**
   * @private
   */

  /**
   * @private
   */

  /**
   * @private
   */

  /**
   * @private
   */
  constructor(bulkLoad) {
    super({
      writableObjectMode: true
    });
    this.bulkLoad = bulkLoad;
    this.mainOptions = bulkLoad.options;
    this.columns = bulkLoad.columns;
    this.columnMetadataWritten = false;
  }

  /**
   * @private
   */
  _transform(row, _encoding, callback) {
    if (!this.columnMetadataWritten) {
      this.push(this.bulkLoad.getColMetaData());
      this.columnMetadataWritten = true;
    }
    this.push(rowTokenBuffer);
    for (let i = 0; i < this.columns.length; i++) {
      const c = this.columns[i];
      let value = Array.isArray(row) ? row[i] : row[c.objName];
      if (!this.bulkLoad.firstRowWritten) {
        try {
          value = c.type.validate(value, c.collation);
        } catch (error) {
          return callback(error);
        }
      }
      const parameter = {
        length: c.length,
        scale: c.scale,
        precision: c.precision,
        value: value
      };
      if (c.type.name === 'Text' || c.type.name === 'Image' || c.type.name === 'NText') {
        if (value == null) {
          this.push(textPointerNullBuffer);
          continue;
        }
        this.push(textPointerAndTimestampBuffer);
      }
      try {
        this.push(c.type.generateParameterLength(parameter, this.mainOptions));
        for (const chunk of c.type.generateParameterData(parameter, this.mainOptions)) {
          this.push(chunk);
        }
      } catch (error) {
        return callback(error);
      }
    }
    process.nextTick(callback);
  }

  /**
   * @private
   */
  _flush(callback) {
    this.push(this.bulkLoad.createDoneToken());
    process.nextTick(callback);
  }
}

/**
 * A BulkLoad instance is used to perform a bulk insert.
 *
 * Use [[Connection.newBulkLoad]] to create a new instance, and [[Connection.execBulkLoad]] to execute it.
 *
 * Example of BulkLoad Usages:
 *
 * ```js
 * // optional BulkLoad options
 * const options = { keepNulls: true };
 *
 * // instantiate - provide the table where you'll be inserting to, options and a callback
 * const bulkLoad = connection.newBulkLoad('MyTable', options, (error, rowCount) => {
 *   console.log('inserted %d rows', rowCount);
 * });
 *
 * // setup your columns - always indicate whether the column is nullable
 * bulkLoad.addColumn('myInt', TYPES.Int, { nullable: false });
 * bulkLoad.addColumn('myString', TYPES.NVarChar, { length: 50, nullable: true });
 *
 * // execute
 * connection.execBulkLoad(bulkLoad, [
 *   { myInt: 7, myString: 'hello' },
 *   { myInt: 23, myString: 'world' }
 * ]);
 * ```
 */
class BulkLoad extends _events.EventEmitter {
  /**
   * @private
   */

  /**
   * @private
   */

  /**
   * @private
   */

  /**
   * @private
   */

  /**
   * @private
   */

  /**
   * @private
   */

  /**
   * @private
   */

  /**
   * @private
   */

  /**
   * @private
   */

  /**
   * @private
   */

  /**
   * @private
   */

  /**
   * @private
   */

  /**
   * @private
   */

  /**
   * @private
   */

  /**
   * @private
   */

  /**
   * @private
   */

  /**
   * @private
   */

  /**
   * @private
   */
  constructor(table, collation, connectionOptions, {
    checkConstraints = false,
    fireTriggers = false,
    keepNulls = false,
    lockTable = false,
    order = {}
  }, callback) {
    if (typeof checkConstraints !== 'boolean') {
      throw new TypeError('The "options.checkConstraints" property must be of type boolean.');
    }
    if (typeof fireTriggers !== 'boolean') {
      throw new TypeError('The "options.fireTriggers" property must be of type boolean.');
    }
    if (typeof keepNulls !== 'boolean') {
      throw new TypeError('The "options.keepNulls" property must be of type boolean.');
    }
    if (typeof lockTable !== 'boolean') {
      throw new TypeError('The "options.lockTable" property must be of type boolean.');
    }
    if (typeof order !== 'object' || order === null) {
      throw new TypeError('The "options.order" property must be of type object.');
    }
    for (const [column, direction] of Object.entries(order)) {
      if (direction !== 'ASC' && direction !== 'DESC') {
        throw new TypeError('The value of the "' + column + '" key in the "options.order" object must be either "ASC" or "DESC".');
      }
    }
    super();
    this.error = undefined;
    this.canceled = false;
    this.executionStarted = false;
    this.collation = collation;
    this.table = table;
    this.options = connectionOptions;
    this.callback = callback;
    this.columns = [];
    this.columnsByName = {};
    this.firstRowWritten = false;
    this.streamingMode = false;
    this.rowToPacketTransform = new RowTransform(this); // eslint-disable-line no-use-before-define

    this.bulkOptions = {
      checkConstraints,
      fireTriggers,
      keepNulls,
      lockTable,
      order
    };
  }

  /**
   * Adds a column to the bulk load.
   *
   * The column definitions should match the table you are trying to insert into.
   * Attempting to call addColumn after the first row has been added will throw an exception.
   *
   * ```js
   * bulkLoad.addColumn('MyIntColumn', TYPES.Int, { nullable: false });
   * ```
   *
   * @param name The name of the column.
   * @param type One of the supported `data types`.
   * @param __namedParameters Additional column type information. At a minimum, `nullable` must be set to true or false.
   * @param length For VarChar, NVarChar, VarBinary. Use length as `Infinity` for VarChar(max), NVarChar(max) and VarBinary(max).
   * @param nullable Indicates whether the column accepts NULL values.
   * @param objName If the name of the column is different from the name of the property found on `rowObj` arguments passed to [[addRow]] or [[Connection.execBulkLoad]], then you can use this option to specify the property name.
   * @param precision For Numeric, Decimal.
   * @param scale For Numeric, Decimal, Time, DateTime2, DateTimeOffset.
  */
  addColumn(name, type, {
    output = false,
    length,
    precision,
    scale,
    objName = name,
    nullable = true
  }) {
    if (this.firstRowWritten) {
      throw new Error('Columns cannot be added to bulk insert after the first row has been written.');
    }
    if (this.executionStarted) {
      throw new Error('Columns cannot be added to bulk insert after execution has started.');
    }
    const column = {
      type: type,
      name: name,
      value: null,
      output: output,
      length: length,
      precision: precision,
      scale: scale,
      objName: objName,
      nullable: nullable,
      collation: this.collation
    };
    if ((type.id & 0x30) === 0x20) {
      if (column.length == null && type.resolveLength) {
        column.length = type.resolveLength(column);
      }
    }
    if (type.resolvePrecision && column.precision == null) {
      column.precision = type.resolvePrecision(column);
    }
    if (type.resolveScale && column.scale == null) {
      column.scale = type.resolveScale(column);
    }
    this.columns.push(column);
    this.columnsByName[name] = column;
  }

  /**
   * @private
   */
  getOptionsSql() {
    const addOptions = [];
    if (this.bulkOptions.checkConstraints) {
      addOptions.push('CHECK_CONSTRAINTS');
    }
    if (this.bulkOptions.fireTriggers) {
      addOptions.push('FIRE_TRIGGERS');
    }
    if (this.bulkOptions.keepNulls) {
      addOptions.push('KEEP_NULLS');
    }
    if (this.bulkOptions.lockTable) {
      addOptions.push('TABLOCK');
    }
    if (this.bulkOptions.order) {
      const orderColumns = [];
      for (const [column, direction] of Object.entries(this.bulkOptions.order)) {
        orderColumns.push(`${column} ${direction}`);
      }
      if (orderColumns.length) {
        addOptions.push(`ORDER (${orderColumns.join(', ')})`);
      }
    }
    if (addOptions.length > 0) {
      return ` WITH (${addOptions.join(',')})`;
    } else {
      return '';
    }
  }

  /**
   * @private
   */
  getBulkInsertSql() {
    let sql = 'insert bulk ' + this.table + '(';
    for (let i = 0, len = this.columns.length; i < len; i++) {
      const c = this.columns[i];
      if (i !== 0) {
        sql += ', ';
      }
      sql += '[' + c.name + '] ' + c.type.declaration(c);
    }
    sql += ')';
    sql += this.getOptionsSql();
    return sql;
  }

  /**
   * This is simply a helper utility function which returns a `CREATE TABLE SQL` statement based on the columns added to the bulkLoad object.
   * This may be particularly handy when you want to insert into a temporary table (a table which starts with `#`).
   *
   * ```js
   * var sql = bulkLoad.getTableCreationSql();
   * ```
   *
   * A side note on bulk inserting into temporary tables: if you want to access a local temporary table after executing the bulk load,
   * you'll need to use the same connection and execute your requests using [[Connection.execSqlBatch]] instead of [[Connection.execSql]]
   */
  getTableCreationSql() {
    let sql = 'CREATE TABLE ' + this.table + '(\n';
    for (let i = 0, len = this.columns.length; i < len; i++) {
      const c = this.columns[i];
      if (i !== 0) {
        sql += ',\n';
      }
      sql += '[' + c.name + '] ' + c.type.declaration(c);
      if (c.nullable !== undefined) {
        sql += ' ' + (c.nullable ? 'NULL' : 'NOT NULL');
      }
    }
    sql += '\n)';
    return sql;
  }

  /**
   * @private
   */
  getColMetaData() {
    const tBuf = new _writableTrackingBuffer.default(100, null, true);
    // TokenType
    tBuf.writeUInt8(_token.TYPE.COLMETADATA);
    // Count
    tBuf.writeUInt16LE(this.columns.length);
    for (let j = 0, len = this.columns.length; j < len; j++) {
      const c = this.columns[j];
      // UserType
      if (this.options.tdsVersion < '7_2') {
        tBuf.writeUInt16LE(0);
      } else {
        tBuf.writeUInt32LE(0);
      }

      // Flags
      let flags = FLAGS.updateableReadWrite;
      if (c.nullable) {
        flags |= FLAGS.nullable;
      } else if (c.nullable === undefined && this.options.tdsVersion >= '7_2') {
        flags |= FLAGS.nullableUnknown;
      }
      tBuf.writeUInt16LE(flags);

      // TYPE_INFO
      tBuf.writeBuffer(c.type.generateTypeInfo(c, this.options));

      // TableName
      if (c.type.hasTableName) {
        tBuf.writeUsVarchar(this.table, 'ucs2');
      }

      // ColName
      tBuf.writeBVarchar(c.name, 'ucs2');
    }
    return tBuf.data;
  }

  /**
   * Sets a timeout for this bulk load.
   *
   * ```js
   * bulkLoad.setTimeout(timeout);
   * ```
   *
   * @param timeout The number of milliseconds before the bulk load is considered failed, or 0 for no timeout.
   *   When no timeout is set for the bulk load, the [[ConnectionOptions.requestTimeout]] of the Connection is used.
   */
  setTimeout(timeout) {
    this.timeout = timeout;
  }

  /**
   * @private
   */
  createDoneToken() {
    // It might be nice to make DoneToken a class if anything needs to create them, but for now, just do it here
    const tBuf = new _writableTrackingBuffer.default(this.options.tdsVersion < '7_2' ? 9 : 13);
    tBuf.writeUInt8(_token.TYPE.DONE);
    const status = DONE_STATUS.FINAL;
    tBuf.writeUInt16LE(status);
    tBuf.writeUInt16LE(0); // CurCmd (TDS ignores this)
    tBuf.writeUInt32LE(0); // row count - doesn't really matter
    if (this.options.tdsVersion >= '7_2') {
      tBuf.writeUInt32LE(0); // row count is 64 bits in >= TDS 7.2
    }
    return tBuf.data;
  }

  /**
   * @private
   */
  cancel() {
    if (this.canceled) {
      return;
    }
    this.canceled = true;
    this.emit('cancel');
  }
}
var _default = exports.default = BulkLoad;
module.exports = BulkLoad;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJuYW1lcyI6WyJfZXZlbnRzIiwicmVxdWlyZSIsIl93cml0YWJsZVRyYWNraW5nQnVmZmVyIiwiX2ludGVyb3BSZXF1aXJlRGVmYXVsdCIsIl9zdHJlYW0iLCJfdG9rZW4iLCJlIiwiX19lc01vZHVsZSIsImRlZmF1bHQiLCJGTEFHUyIsIm51bGxhYmxlIiwiY2FzZVNlbiIsInVwZGF0ZWFibGVSZWFkV3JpdGUiLCJ1cGRhdGVhYmxlVW5rbm93biIsImlkZW50aXR5IiwiY29tcHV0ZWQiLCJmaXhlZExlbkNMUlR5cGUiLCJzcGFyc2VDb2x1bW5TZXQiLCJoaWRkZW4iLCJrZXkiLCJudWxsYWJsZVVua25vd24iLCJET05FX1NUQVRVUyIsIkZJTkFMIiwiTU9SRSIsIkVSUk9SIiwiSU5YQUNUIiwiQ09VTlQiLCJBVFROIiwiU1JWRVJST1IiLCJyb3dUb2tlbkJ1ZmZlciIsIkJ1ZmZlciIsImZyb20iLCJUT0tFTl9UWVBFIiwiUk9XIiwidGV4dFBvaW50ZXJBbmRUaW1lc3RhbXBCdWZmZXIiLCJ0ZXh0UG9pbnRlck51bGxCdWZmZXIiLCJSb3dUcmFuc2Zvcm0iLCJUcmFuc2Zvcm0iLCJjb25zdHJ1Y3RvciIsImJ1bGtMb2FkIiwid3JpdGFibGVPYmplY3RNb2RlIiwibWFpbk9wdGlvbnMiLCJvcHRpb25zIiwiY29sdW1ucyIsImNvbHVtbk1ldGFkYXRhV3JpdHRlbiIsIl90cmFuc2Zvcm0iLCJyb3ciLCJfZW5jb2RpbmciLCJjYWxsYmFjayIsInB1c2giLCJnZXRDb2xNZXRhRGF0YSIsImkiLCJsZW5ndGgiLCJjIiwidmFsdWUiLCJBcnJheSIsImlzQXJyYXkiLCJvYmpOYW1lIiwiZmlyc3RSb3dXcml0dGVuIiwidHlwZSIsInZhbGlkYXRlIiwiY29sbGF0aW9uIiwiZXJyb3IiLCJwYXJhbWV0ZXIiLCJzY2FsZSIsInByZWNpc2lvbiIsIm5hbWUiLCJnZW5lcmF0ZVBhcmFtZXRlckxlbmd0aCIsImNodW5rIiwiZ2VuZXJhdGVQYXJhbWV0ZXJEYXRhIiwicHJvY2VzcyIsIm5leHRUaWNrIiwiX2ZsdXNoIiwiY3JlYXRlRG9uZVRva2VuIiwiQnVsa0xvYWQiLCJFdmVudEVtaXR0ZXIiLCJ0YWJsZSIsImNvbm5lY3Rpb25PcHRpb25zIiwiY2hlY2tDb25zdHJhaW50cyIsImZpcmVUcmlnZ2VycyIsImtlZXBOdWxscyIsImxvY2tUYWJsZSIsIm9yZGVyIiwiVHlwZUVycm9yIiwiY29sdW1uIiwiZGlyZWN0aW9uIiwiT2JqZWN0IiwiZW50cmllcyIsInVuZGVmaW5lZCIsImNhbmNlbGVkIiwiZXhlY3V0aW9uU3RhcnRlZCIsImNvbHVtbnNCeU5hbWUiLCJzdHJlYW1pbmdNb2RlIiwicm93VG9QYWNrZXRUcmFuc2Zvcm0iLCJidWxrT3B0aW9ucyIsImFkZENvbHVtbiIsIm91dHB1dCIsIkVycm9yIiwiaWQiLCJyZXNvbHZlTGVuZ3RoIiwicmVzb2x2ZVByZWNpc2lvbiIsInJlc29sdmVTY2FsZSIsImdldE9wdGlvbnNTcWwiLCJhZGRPcHRpb25zIiwib3JkZXJDb2x1bW5zIiwiam9pbiIsImdldEJ1bGtJbnNlcnRTcWwiLCJzcWwiLCJsZW4iLCJkZWNsYXJhdGlvbiIsImdldFRhYmxlQ3JlYXRpb25TcWwiLCJ0QnVmIiwiV3JpdGFibGVUcmFja2luZ0J1ZmZlciIsIndyaXRlVUludDgiLCJDT0xNRVRBREFUQSIsIndyaXRlVUludDE2TEUiLCJqIiwidGRzVmVyc2lvbiIsIndyaXRlVUludDMyTEUiLCJmbGFncyIsIndyaXRlQnVmZmVyIiwiZ2VuZXJhdGVUeXBlSW5mbyIsImhhc1RhYmxlTmFtZSIsIndyaXRlVXNWYXJjaGFyIiwid3JpdGVCVmFyY2hhciIsImRhdGEiLCJzZXRUaW1lb3V0IiwidGltZW91dCIsIkRPTkUiLCJzdGF0dXMiLCJjYW5jZWwiLCJlbWl0IiwiX2RlZmF1bHQiLCJleHBvcnRzIiwibW9kdWxlIl0sInNvdXJjZXMiOlsiLi4vc3JjL2J1bGstbG9hZC50cyJdLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBFdmVudEVtaXR0ZXIgfSBmcm9tICdldmVudHMnO1xuaW1wb3J0IFdyaXRhYmxlVHJhY2tpbmdCdWZmZXIgZnJvbSAnLi90cmFja2luZy1idWZmZXIvd3JpdGFibGUtdHJhY2tpbmctYnVmZmVyJztcbmltcG9ydCBDb25uZWN0aW9uLCB7IHR5cGUgSW50ZXJuYWxDb25uZWN0aW9uT3B0aW9ucyB9IGZyb20gJy4vY29ubmVjdGlvbic7XG5cbmltcG9ydCB7IFRyYW5zZm9ybSB9IGZyb20gJ3N0cmVhbSc7XG5pbXBvcnQgeyBUWVBFIGFzIFRPS0VOX1RZUEUgfSBmcm9tICcuL3Rva2VuL3Rva2VuJztcblxuaW1wb3J0IHsgdHlwZSBEYXRhVHlwZSwgdHlwZSBQYXJhbWV0ZXIgfSBmcm9tICcuL2RhdGEtdHlwZSc7XG5pbXBvcnQgeyBDb2xsYXRpb24gfSBmcm9tICcuL2NvbGxhdGlvbic7XG5cbi8qKlxuICogQHByaXZhdGVcbiAqL1xuY29uc3QgRkxBR1MgPSB7XG4gIG51bGxhYmxlOiAxIDw8IDAsXG4gIGNhc2VTZW46IDEgPDwgMSxcbiAgdXBkYXRlYWJsZVJlYWRXcml0ZTogMSA8PCAyLFxuICB1cGRhdGVhYmxlVW5rbm93bjogMSA8PCAzLFxuICBpZGVudGl0eTogMSA8PCA0LFxuICBjb21wdXRlZDogMSA8PCA1LCAvLyBpbnRyb2R1Y2VkIGluIFREUyA3LjJcbiAgZml4ZWRMZW5DTFJUeXBlOiAxIDw8IDgsIC8vIGludHJvZHVjZWQgaW4gVERTIDcuMlxuICBzcGFyc2VDb2x1bW5TZXQ6IDEgPDwgMTAsIC8vIGludHJvZHVjZWQgaW4gVERTIDcuMy5CXG4gIGhpZGRlbjogMSA8PCAxMywgLy8gaW50cm9kdWNlZCBpbiBURFMgNy4yXG4gIGtleTogMSA8PCAxNCwgLy8gaW50cm9kdWNlZCBpbiBURFMgNy4yXG4gIG51bGxhYmxlVW5rbm93bjogMSA8PCAxNSAvLyBpbnRyb2R1Y2VkIGluIFREUyA3LjJcbn07XG5cbi8qKlxuICogQHByaXZhdGVcbiAqL1xuY29uc3QgRE9ORV9TVEFUVVMgPSB7XG4gIEZJTkFMOiAweDAwLFxuICBNT1JFOiAweDEsXG4gIEVSUk9SOiAweDIsXG4gIElOWEFDVDogMHg0LFxuICBDT1VOVDogMHgxMCxcbiAgQVRUTjogMHgyMCxcbiAgU1JWRVJST1I6IDB4MTAwXG59O1xuXG4vKipcbiAqIEBwcml2YXRlXG4gKi9cbmludGVyZmFjZSBJbnRlcm5hbE9wdGlvbnMge1xuICBjaGVja0NvbnN0cmFpbnRzOiBib29sZWFuO1xuICBmaXJlVHJpZ2dlcnM6IGJvb2xlYW47XG4gIGtlZXBOdWxsczogYm9vbGVhbjtcbiAgbG9ja1RhYmxlOiBib29sZWFuO1xuICBvcmRlcjogeyBbY29sdW1uTmFtZTogc3RyaW5nXTogJ0FTQycgfCAnREVTQycgfTtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBPcHRpb25zIHtcbiAgLyoqXG4gICAqIEhvbm9ycyBjb25zdHJhaW50cyBkdXJpbmcgYnVsayBsb2FkLCB1c2luZyBULVNRTFxuICAgKiBbQ0hFQ0tfQ09OU1RSQUlOVFNdKGh0dHBzOi8vdGVjaG5ldC5taWNyb3NvZnQuY29tL2VuLXVzL2xpYnJhcnkvbXMxODYyNDcodj1zcWwuMTA1KS5hc3B4KS5cbiAgICogKGRlZmF1bHQ6IGBmYWxzZWApXG4gICAqL1xuICBjaGVja0NvbnN0cmFpbnRzPzogSW50ZXJuYWxPcHRpb25zWydjaGVja0NvbnN0cmFpbnRzJ10gfCB1bmRlZmluZWQ7XG5cbiAgLyoqXG4gICAqIEhvbm9ycyBpbnNlcnQgdHJpZ2dlcnMgZHVyaW5nIGJ1bGsgbG9hZCwgdXNpbmcgdGhlIFQtU1FMIFtGSVJFX1RSSUdHRVJTXShodHRwczovL3RlY2huZXQubWljcm9zb2Z0LmNvbS9lbi11cy9saWJyYXJ5L21zMTg3NjQwKHY9c3FsLjEwNSkuYXNweCkuIChkZWZhdWx0OiBgZmFsc2VgKVxuICAgKi9cbiAgZmlyZVRyaWdnZXJzPzogSW50ZXJuYWxPcHRpb25zWydmaXJlVHJpZ2dlcnMnXSB8IHVuZGVmaW5lZDtcblxuICAvKipcbiAgICogSG9ub3JzIG51bGwgdmFsdWUgcGFzc2VkLCBpZ25vcmVzIHRoZSBkZWZhdWx0IHZhbHVlcyBzZXQgb24gdGFibGUsIHVzaW5nIFQtU1FMIFtLRUVQX05VTExTXShodHRwczovL21zZG4ubWljcm9zb2Z0LmNvbS9lbi11cy9saWJyYXJ5L21zMTg3ODg3KHY9c3FsLjEyMCkuYXNweCkuIChkZWZhdWx0OiBgZmFsc2VgKVxuICAgKi9cbiAga2VlcE51bGxzPzogSW50ZXJuYWxPcHRpb25zWydrZWVwTnVsbHMnXSB8IHVuZGVmaW5lZDtcblxuICAvKipcbiAgICogUGxhY2VzIGEgYnVsayB1cGRhdGUoQlUpIGxvY2sgb24gdGFibGUgd2hpbGUgcGVyZm9ybWluZyBidWxrIGxvYWQsIHVzaW5nIFQtU1FMIFtUQUJMT0NLXShodHRwczovL3RlY2huZXQubWljcm9zb2Z0LmNvbS9lbi11cy9saWJyYXJ5L21zMTgwODc2KHY9c3FsLjEwNSkuYXNweCkuIChkZWZhdWx0OiBgZmFsc2VgKVxuICAgKi9cbiAgbG9ja1RhYmxlPzogSW50ZXJuYWxPcHRpb25zWydsb2NrVGFibGUnXSB8IHVuZGVmaW5lZDtcblxuICAvKipcbiAgICogU3BlY2lmaWVzIHRoZSBvcmRlcmluZyBvZiB0aGUgZGF0YSB0byBwb3NzaWJseSBpbmNyZWFzZSBidWxrIGluc2VydCBwZXJmb3JtYW5jZSwgdXNpbmcgVC1TUUwgW09SREVSXShodHRwczovL2RvY3MubWljcm9zb2Z0LmNvbS9lbi11cy9wcmV2aW91cy12ZXJzaW9ucy9zcWwvc3FsLXNlcnZlci0yMDA4LXIyL21zMTc3NDY4KHY9c3FsLjEwNSkpLiAoZGVmYXVsdDogYHt9YClcbiAgICovXG4gIG9yZGVyPzogSW50ZXJuYWxPcHRpb25zWydvcmRlciddIHwgdW5kZWZpbmVkO1xufVxuXG5cbmV4cG9ydCB0eXBlIENhbGxiYWNrID1cbiAgLyoqXG4gICAqIEEgZnVuY3Rpb24gd2hpY2ggd2lsbCBiZSBjYWxsZWQgYWZ0ZXIgdGhlIFtbQnVsa0xvYWRdXSBmaW5pc2hlcyBleGVjdXRpbmcuXG4gICAqXG4gICAqIEBwYXJhbSByb3dDb3VudCB0aGUgbnVtYmVyIG9mIHJvd3MgaW5zZXJ0ZWRcbiAgICovXG4gIChlcnI6IEVycm9yIHwgdW5kZWZpbmVkIHwgbnVsbCwgcm93Q291bnQ/OiBudW1iZXIpID0+IHZvaWQ7XG5cbmludGVyZmFjZSBDb2x1bW4gZXh0ZW5kcyBQYXJhbWV0ZXIge1xuICBvYmpOYW1lOiBzdHJpbmc7XG4gIGNvbGxhdGlvbjogQ29sbGF0aW9uIHwgdW5kZWZpbmVkO1xufVxuXG5pbnRlcmZhY2UgQ29sdW1uT3B0aW9ucyB7XG4gIG91dHB1dD86IGJvb2xlYW47XG5cbiAgLyoqXG4gICAqIEZvciBWYXJDaGFyLCBOVmFyQ2hhciwgVmFyQmluYXJ5LiBVc2UgbGVuZ3RoIGFzIGBJbmZpbml0eWAgZm9yIFZhckNoYXIobWF4KSwgTlZhckNoYXIobWF4KSBhbmQgVmFyQmluYXJ5KG1heCkuXG4gICAqL1xuICBsZW5ndGg/OiBudW1iZXI7XG5cbiAgLyoqXG4gICAqIEZvciBOdW1lcmljLCBEZWNpbWFsLlxuICAgKi9cbiAgcHJlY2lzaW9uPzogbnVtYmVyO1xuXG4gIC8qKlxuICAgKiBGb3IgTnVtZXJpYywgRGVjaW1hbCwgVGltZSwgRGF0ZVRpbWUyLCBEYXRlVGltZU9mZnNldC5cbiAgICovXG4gIHNjYWxlPzogbnVtYmVyO1xuXG4gIC8qKlxuICAgKiBJZiB0aGUgbmFtZSBvZiB0aGUgY29sdW1uIGlzIGRpZmZlcmVudCBmcm9tIHRoZSBuYW1lIG9mIHRoZSBwcm9wZXJ0eSBmb3VuZCBvbiBgcm93T2JqYCBhcmd1bWVudHMgcGFzc2VkIHRvIFtbYWRkUm93XV0sIHRoZW4geW91IGNhbiB1c2UgdGhpcyBvcHRpb24gdG8gc3BlY2lmeSB0aGUgcHJvcGVydHkgbmFtZS5cbiAgICovXG4gIG9iak5hbWU/OiBzdHJpbmc7XG5cbiAgLyoqXG4gICAqIEluZGljYXRlcyB3aGV0aGVyIHRoZSBjb2x1bW4gYWNjZXB0cyBOVUxMIHZhbHVlcy5cbiAgICovXG4gIG51bGxhYmxlPzogYm9vbGVhbjtcbn1cblxuY29uc3Qgcm93VG9rZW5CdWZmZXIgPSBCdWZmZXIuZnJvbShbIFRPS0VOX1RZUEUuUk9XIF0pO1xuY29uc3QgdGV4dFBvaW50ZXJBbmRUaW1lc3RhbXBCdWZmZXIgPSBCdWZmZXIuZnJvbShbXG4gIC8vIFRleHRQb2ludGVyIGxlbmd0aFxuICAweDEwLFxuXG4gIC8vIFRleHRQb2ludGVyXG4gIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsXG5cbiAgLy8gVGltZXN0YW1wXG4gIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDBcbl0pO1xuY29uc3QgdGV4dFBvaW50ZXJOdWxsQnVmZmVyID0gQnVmZmVyLmZyb20oWzB4MDBdKTtcblxuLy8gQSB0cmFuc2Zvcm0gdGhhdCBjb252ZXJ0cyByb3dzIHRvIHBhY2tldHMuXG5jbGFzcyBSb3dUcmFuc2Zvcm0gZXh0ZW5kcyBUcmFuc2Zvcm0ge1xuICAvKipcbiAgICogQHByaXZhdGVcbiAgICovXG4gIGRlY2xhcmUgY29sdW1uTWV0YWRhdGFXcml0dGVuOiBib29sZWFuO1xuICAvKipcbiAgICogQHByaXZhdGVcbiAgICovXG4gIGRlY2xhcmUgYnVsa0xvYWQ6IEJ1bGtMb2FkO1xuICAvKipcbiAgICogQHByaXZhdGVcbiAgICovXG4gIGRlY2xhcmUgbWFpbk9wdGlvbnM6IEJ1bGtMb2FkWydvcHRpb25zJ107XG4gIC8qKlxuICAgKiBAcHJpdmF0ZVxuICAgKi9cbiAgZGVjbGFyZSBjb2x1bW5zOiBCdWxrTG9hZFsnY29sdW1ucyddO1xuXG4gIC8qKlxuICAgKiBAcHJpdmF0ZVxuICAgKi9cbiAgY29uc3RydWN0b3IoYnVsa0xvYWQ6IEJ1bGtMb2FkKSB7XG4gICAgc3VwZXIoeyB3cml0YWJsZU9iamVjdE1vZGU6IHRydWUgfSk7XG5cbiAgICB0aGlzLmJ1bGtMb2FkID0gYnVsa0xvYWQ7XG4gICAgdGhpcy5tYWluT3B0aW9ucyA9IGJ1bGtMb2FkLm9wdGlvbnM7XG4gICAgdGhpcy5jb2x1bW5zID0gYnVsa0xvYWQuY29sdW1ucztcblxuICAgIHRoaXMuY29sdW1uTWV0YWRhdGFXcml0dGVuID0gZmFsc2U7XG4gIH1cblxuICAvKipcbiAgICogQHByaXZhdGVcbiAgICovXG4gIF90cmFuc2Zvcm0ocm93OiBBcnJheTx1bmtub3duPiB8IHsgW2NvbE5hbWU6IHN0cmluZ106IHVua25vd24gfSwgX2VuY29kaW5nOiBzdHJpbmcsIGNhbGxiYWNrOiAoZXJyb3I/OiBFcnJvcikgPT4gdm9pZCkge1xuICAgIGlmICghdGhpcy5jb2x1bW5NZXRhZGF0YVdyaXR0ZW4pIHtcbiAgICAgIHRoaXMucHVzaCh0aGlzLmJ1bGtMb2FkLmdldENvbE1ldGFEYXRhKCkpO1xuICAgICAgdGhpcy5jb2x1bW5NZXRhZGF0YVdyaXR0ZW4gPSB0cnVlO1xuICAgIH1cblxuICAgIHRoaXMucHVzaChyb3dUb2tlbkJ1ZmZlcik7XG5cbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IHRoaXMuY29sdW1ucy5sZW5ndGg7IGkrKykge1xuICAgICAgY29uc3QgYyA9IHRoaXMuY29sdW1uc1tpXTtcbiAgICAgIGxldCB2YWx1ZSA9IEFycmF5LmlzQXJyYXkocm93KSA/IHJvd1tpXSA6IHJvd1tjLm9iak5hbWVdO1xuXG4gICAgICBpZiAoIXRoaXMuYnVsa0xvYWQuZmlyc3RSb3dXcml0dGVuKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgdmFsdWUgPSBjLnR5cGUudmFsaWRhdGUodmFsdWUsIGMuY29sbGF0aW9uKTtcbiAgICAgICAgfSBjYXRjaCAoZXJyb3I6IGFueSkge1xuICAgICAgICAgIHJldHVybiBjYWxsYmFjayhlcnJvcik7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgY29uc3QgcGFyYW1ldGVyID0ge1xuICAgICAgICBsZW5ndGg6IGMubGVuZ3RoLFxuICAgICAgICBzY2FsZTogYy5zY2FsZSxcbiAgICAgICAgcHJlY2lzaW9uOiBjLnByZWNpc2lvbixcbiAgICAgICAgdmFsdWU6IHZhbHVlXG4gICAgICB9O1xuXG4gICAgICBpZiAoYy50eXBlLm5hbWUgPT09ICdUZXh0JyB8fCBjLnR5cGUubmFtZSA9PT0gJ0ltYWdlJyB8fCBjLnR5cGUubmFtZSA9PT0gJ05UZXh0Jykge1xuICAgICAgICBpZiAodmFsdWUgPT0gbnVsbCkge1xuICAgICAgICAgIHRoaXMucHVzaCh0ZXh0UG9pbnRlck51bGxCdWZmZXIpO1xuICAgICAgICAgIGNvbnRpbnVlO1xuICAgICAgICB9XG5cbiAgICAgICAgdGhpcy5wdXNoKHRleHRQb2ludGVyQW5kVGltZXN0YW1wQnVmZmVyKTtcbiAgICAgIH1cblxuICAgICAgdHJ5IHtcbiAgICAgICAgdGhpcy5wdXNoKGMudHlwZS5nZW5lcmF0ZVBhcmFtZXRlckxlbmd0aChwYXJhbWV0ZXIsIHRoaXMubWFpbk9wdGlvbnMpKTtcbiAgICAgICAgZm9yIChjb25zdCBjaHVuayBvZiBjLnR5cGUuZ2VuZXJhdGVQYXJhbWV0ZXJEYXRhKHBhcmFtZXRlciwgdGhpcy5tYWluT3B0aW9ucykpIHtcbiAgICAgICAgICB0aGlzLnB1c2goY2h1bmspO1xuICAgICAgICB9XG4gICAgICB9IGNhdGNoIChlcnJvcjogYW55KSB7XG4gICAgICAgIHJldHVybiBjYWxsYmFjayhlcnJvcik7XG4gICAgICB9XG4gICAgfVxuXG4gICAgcHJvY2Vzcy5uZXh0VGljayhjYWxsYmFjayk7XG4gIH1cblxuICAvKipcbiAgICogQHByaXZhdGVcbiAgICovXG4gIF9mbHVzaChjYWxsYmFjazogKCkgPT4gdm9pZCkge1xuICAgIHRoaXMucHVzaCh0aGlzLmJ1bGtMb2FkLmNyZWF0ZURvbmVUb2tlbigpKTtcblxuICAgIHByb2Nlc3MubmV4dFRpY2soY2FsbGJhY2spO1xuICB9XG59XG5cbi8qKlxuICogQSBCdWxrTG9hZCBpbnN0YW5jZSBpcyB1c2VkIHRvIHBlcmZvcm0gYSBidWxrIGluc2VydC5cbiAqXG4gKiBVc2UgW1tDb25uZWN0aW9uLm5ld0J1bGtMb2FkXV0gdG8gY3JlYXRlIGEgbmV3IGluc3RhbmNlLCBhbmQgW1tDb25uZWN0aW9uLmV4ZWNCdWxrTG9hZF1dIHRvIGV4ZWN1dGUgaXQuXG4gKlxuICogRXhhbXBsZSBvZiBCdWxrTG9hZCBVc2FnZXM6XG4gKlxuICogYGBganNcbiAqIC8vIG9wdGlvbmFsIEJ1bGtMb2FkIG9wdGlvbnNcbiAqIGNvbnN0IG9wdGlvbnMgPSB7IGtlZXBOdWxsczogdHJ1ZSB9O1xuICpcbiAqIC8vIGluc3RhbnRpYXRlIC0gcHJvdmlkZSB0aGUgdGFibGUgd2hlcmUgeW91J2xsIGJlIGluc2VydGluZyB0bywgb3B0aW9ucyBhbmQgYSBjYWxsYmFja1xuICogY29uc3QgYnVsa0xvYWQgPSBjb25uZWN0aW9uLm5ld0J1bGtMb2FkKCdNeVRhYmxlJywgb3B0aW9ucywgKGVycm9yLCByb3dDb3VudCkgPT4ge1xuICogICBjb25zb2xlLmxvZygnaW5zZXJ0ZWQgJWQgcm93cycsIHJvd0NvdW50KTtcbiAqIH0pO1xuICpcbiAqIC8vIHNldHVwIHlvdXIgY29sdW1ucyAtIGFsd2F5cyBpbmRpY2F0ZSB3aGV0aGVyIHRoZSBjb2x1bW4gaXMgbnVsbGFibGVcbiAqIGJ1bGtMb2FkLmFkZENvbHVtbignbXlJbnQnLCBUWVBFUy5JbnQsIHsgbnVsbGFibGU6IGZhbHNlIH0pO1xuICogYnVsa0xvYWQuYWRkQ29sdW1uKCdteVN0cmluZycsIFRZUEVTLk5WYXJDaGFyLCB7IGxlbmd0aDogNTAsIG51bGxhYmxlOiB0cnVlIH0pO1xuICpcbiAqIC8vIGV4ZWN1dGVcbiAqIGNvbm5lY3Rpb24uZXhlY0J1bGtMb2FkKGJ1bGtMb2FkLCBbXG4gKiAgIHsgbXlJbnQ6IDcsIG15U3RyaW5nOiAnaGVsbG8nIH0sXG4gKiAgIHsgbXlJbnQ6IDIzLCBteVN0cmluZzogJ3dvcmxkJyB9XG4gKiBdKTtcbiAqIGBgYFxuICovXG5jbGFzcyBCdWxrTG9hZCBleHRlbmRzIEV2ZW50RW1pdHRlciB7XG4gIC8qKlxuICAgKiBAcHJpdmF0ZVxuICAgKi9cbiAgZGVjbGFyZSBlcnJvcjogRXJyb3IgfCB1bmRlZmluZWQ7XG4gIC8qKlxuICAgKiBAcHJpdmF0ZVxuICAgKi9cbiAgZGVjbGFyZSBjYW5jZWxlZDogYm9vbGVhbjtcbiAgLyoqXG4gICAqIEBwcml2YXRlXG4gICAqL1xuICBkZWNsYXJlIGV4ZWN1dGlvblN0YXJ0ZWQ6IGJvb2xlYW47XG4gIC8qKlxuICAgKiBAcHJpdmF0ZVxuICAgKi9cbiAgZGVjbGFyZSBzdHJlYW1pbmdNb2RlOiBib29sZWFuO1xuICAvKipcbiAgICogQHByaXZhdGVcbiAgICovXG4gIGRlY2xhcmUgdGFibGU6IHN0cmluZztcbiAgLyoqXG4gICAqIEBwcml2YXRlXG4gICAqL1xuICBkZWNsYXJlIHRpbWVvdXQ6IG51bWJlciB8IHVuZGVmaW5lZDtcblxuICAvKipcbiAgICogQHByaXZhdGVcbiAgICovXG4gIGRlY2xhcmUgb3B0aW9uczogSW50ZXJuYWxDb25uZWN0aW9uT3B0aW9ucztcbiAgLyoqXG4gICAqIEBwcml2YXRlXG4gICAqL1xuICBkZWNsYXJlIGNhbGxiYWNrOiBDYWxsYmFjaztcblxuICAvKipcbiAgICogQHByaXZhdGVcbiAgICovXG4gIGRlY2xhcmUgY29sdW1uczogQXJyYXk8Q29sdW1uPjtcbiAgLyoqXG4gICAqIEBwcml2YXRlXG4gICAqL1xuICBkZWNsYXJlIGNvbHVtbnNCeU5hbWU6IHsgW25hbWU6IHN0cmluZ106IENvbHVtbiB9O1xuXG4gIC8qKlxuICAgKiBAcHJpdmF0ZVxuICAgKi9cbiAgZGVjbGFyZSBmaXJzdFJvd1dyaXR0ZW46IGJvb2xlYW47XG4gIC8qKlxuICAgKiBAcHJpdmF0ZVxuICAgKi9cbiAgZGVjbGFyZSByb3dUb1BhY2tldFRyYW5zZm9ybTogUm93VHJhbnNmb3JtO1xuXG4gIC8qKlxuICAgKiBAcHJpdmF0ZVxuICAgKi9cbiAgZGVjbGFyZSBidWxrT3B0aW9uczogSW50ZXJuYWxPcHRpb25zO1xuXG4gIC8qKlxuICAgKiBAcHJpdmF0ZVxuICAgKi9cbiAgZGVjbGFyZSBjb25uZWN0aW9uOiBDb25uZWN0aW9uIHwgdW5kZWZpbmVkO1xuICAvKipcbiAgICogQHByaXZhdGVcbiAgICovXG4gIGRlY2xhcmUgcm93czogQXJyYXk8YW55PiB8IHVuZGVmaW5lZDtcbiAgLyoqXG4gICAqIEBwcml2YXRlXG4gICAqL1xuICBkZWNsYXJlIHJzdDogQXJyYXk8YW55PiB8IHVuZGVmaW5lZDtcbiAgLyoqXG4gICAqIEBwcml2YXRlXG4gICAqL1xuICBkZWNsYXJlIHJvd0NvdW50OiBudW1iZXIgfCB1bmRlZmluZWQ7XG5cbiAgZGVjbGFyZSBjb2xsYXRpb246IENvbGxhdGlvbiB8IHVuZGVmaW5lZDtcblxuICAvKipcbiAgICogQHByaXZhdGVcbiAgICovXG4gIGNvbnN0cnVjdG9yKHRhYmxlOiBzdHJpbmcsIGNvbGxhdGlvbjogQ29sbGF0aW9uIHwgdW5kZWZpbmVkLCBjb25uZWN0aW9uT3B0aW9uczogSW50ZXJuYWxDb25uZWN0aW9uT3B0aW9ucywge1xuICAgIGNoZWNrQ29uc3RyYWludHMgPSBmYWxzZSxcbiAgICBmaXJlVHJpZ2dlcnMgPSBmYWxzZSxcbiAgICBrZWVwTnVsbHMgPSBmYWxzZSxcbiAgICBsb2NrVGFibGUgPSBmYWxzZSxcbiAgICBvcmRlciA9IHt9LFxuICB9OiBPcHRpb25zLCBjYWxsYmFjazogQ2FsbGJhY2spIHtcbiAgICBpZiAodHlwZW9mIGNoZWNrQ29uc3RyYWludHMgIT09ICdib29sZWFuJykge1xuICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignVGhlIFwib3B0aW9ucy5jaGVja0NvbnN0cmFpbnRzXCIgcHJvcGVydHkgbXVzdCBiZSBvZiB0eXBlIGJvb2xlYW4uJyk7XG4gICAgfVxuXG4gICAgaWYgKHR5cGVvZiBmaXJlVHJpZ2dlcnMgIT09ICdib29sZWFuJykge1xuICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignVGhlIFwib3B0aW9ucy5maXJlVHJpZ2dlcnNcIiBwcm9wZXJ0eSBtdXN0IGJlIG9mIHR5cGUgYm9vbGVhbi4nKTtcbiAgICB9XG5cbiAgICBpZiAodHlwZW9mIGtlZXBOdWxscyAhPT0gJ2Jvb2xlYW4nKSB7XG4gICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdUaGUgXCJvcHRpb25zLmtlZXBOdWxsc1wiIHByb3BlcnR5IG11c3QgYmUgb2YgdHlwZSBib29sZWFuLicpO1xuICAgIH1cblxuICAgIGlmICh0eXBlb2YgbG9ja1RhYmxlICE9PSAnYm9vbGVhbicpIHtcbiAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1RoZSBcIm9wdGlvbnMubG9ja1RhYmxlXCIgcHJvcGVydHkgbXVzdCBiZSBvZiB0eXBlIGJvb2xlYW4uJyk7XG4gICAgfVxuXG4gICAgaWYgKHR5cGVvZiBvcmRlciAhPT0gJ29iamVjdCcgfHwgb3JkZXIgPT09IG51bGwpIHtcbiAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1RoZSBcIm9wdGlvbnMub3JkZXJcIiBwcm9wZXJ0eSBtdXN0IGJlIG9mIHR5cGUgb2JqZWN0LicpO1xuICAgIH1cblxuICAgIGZvciAoY29uc3QgW2NvbHVtbiwgZGlyZWN0aW9uXSBvZiBPYmplY3QuZW50cmllcyhvcmRlcikpIHtcbiAgICAgIGlmIChkaXJlY3Rpb24gIT09ICdBU0MnICYmIGRpcmVjdGlvbiAhPT0gJ0RFU0MnKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1RoZSB2YWx1ZSBvZiB0aGUgXCInICsgY29sdW1uICsgJ1wiIGtleSBpbiB0aGUgXCJvcHRpb25zLm9yZGVyXCIgb2JqZWN0IG11c3QgYmUgZWl0aGVyIFwiQVNDXCIgb3IgXCJERVNDXCIuJyk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgc3VwZXIoKTtcblxuICAgIHRoaXMuZXJyb3IgPSB1bmRlZmluZWQ7XG4gICAgdGhpcy5jYW5jZWxlZCA9IGZhbHNlO1xuICAgIHRoaXMuZXhlY3V0aW9uU3RhcnRlZCA9IGZhbHNlO1xuXG4gICAgdGhpcy5jb2xsYXRpb24gPSBjb2xsYXRpb247XG5cbiAgICB0aGlzLnRhYmxlID0gdGFibGU7XG4gICAgdGhpcy5vcHRpb25zID0gY29ubmVjdGlvbk9wdGlvbnM7XG4gICAgdGhpcy5jYWxsYmFjayA9IGNhbGxiYWNrO1xuICAgIHRoaXMuY29sdW1ucyA9IFtdO1xuICAgIHRoaXMuY29sdW1uc0J5TmFtZSA9IHt9O1xuICAgIHRoaXMuZmlyc3RSb3dXcml0dGVuID0gZmFsc2U7XG4gICAgdGhpcy5zdHJlYW1pbmdNb2RlID0gZmFsc2U7XG5cbiAgICB0aGlzLnJvd1RvUGFja2V0VHJhbnNmb3JtID0gbmV3IFJvd1RyYW5zZm9ybSh0aGlzKTsgLy8gZXNsaW50LWRpc2FibGUtbGluZSBuby11c2UtYmVmb3JlLWRlZmluZVxuXG4gICAgdGhpcy5idWxrT3B0aW9ucyA9IHsgY2hlY2tDb25zdHJhaW50cywgZmlyZVRyaWdnZXJzLCBrZWVwTnVsbHMsIGxvY2tUYWJsZSwgb3JkZXIgfTtcbiAgfVxuXG4gIC8qKlxuICAgKiBBZGRzIGEgY29sdW1uIHRvIHRoZSBidWxrIGxvYWQuXG4gICAqXG4gICAqIFRoZSBjb2x1bW4gZGVmaW5pdGlvbnMgc2hvdWxkIG1hdGNoIHRoZSB0YWJsZSB5b3UgYXJlIHRyeWluZyB0byBpbnNlcnQgaW50by5cbiAgICogQXR0ZW1wdGluZyB0byBjYWxsIGFkZENvbHVtbiBhZnRlciB0aGUgZmlyc3Qgcm93IGhhcyBiZWVuIGFkZGVkIHdpbGwgdGhyb3cgYW4gZXhjZXB0aW9uLlxuICAgKlxuICAgKiBgYGBqc1xuICAgKiBidWxrTG9hZC5hZGRDb2x1bW4oJ015SW50Q29sdW1uJywgVFlQRVMuSW50LCB7IG51bGxhYmxlOiBmYWxzZSB9KTtcbiAgICogYGBgXG4gICAqXG4gICAqIEBwYXJhbSBuYW1lIFRoZSBuYW1lIG9mIHRoZSBjb2x1bW4uXG4gICAqIEBwYXJhbSB0eXBlIE9uZSBvZiB0aGUgc3VwcG9ydGVkIGBkYXRhIHR5cGVzYC5cbiAgICogQHBhcmFtIF9fbmFtZWRQYXJhbWV0ZXJzIEFkZGl0aW9uYWwgY29sdW1uIHR5cGUgaW5mb3JtYXRpb24uIEF0IGEgbWluaW11bSwgYG51bGxhYmxlYCBtdXN0IGJlIHNldCB0byB0cnVlIG9yIGZhbHNlLlxuICAgKiBAcGFyYW0gbGVuZ3RoIEZvciBWYXJDaGFyLCBOVmFyQ2hhciwgVmFyQmluYXJ5LiBVc2UgbGVuZ3RoIGFzIGBJbmZpbml0eWAgZm9yIFZhckNoYXIobWF4KSwgTlZhckNoYXIobWF4KSBhbmQgVmFyQmluYXJ5KG1heCkuXG4gICAqIEBwYXJhbSBudWxsYWJsZSBJbmRpY2F0ZXMgd2hldGhlciB0aGUgY29sdW1uIGFjY2VwdHMgTlVMTCB2YWx1ZXMuXG4gICAqIEBwYXJhbSBvYmpOYW1lIElmIHRoZSBuYW1lIG9mIHRoZSBjb2x1bW4gaXMgZGlmZmVyZW50IGZyb20gdGhlIG5hbWUgb2YgdGhlIHByb3BlcnR5IGZvdW5kIG9uIGByb3dPYmpgIGFyZ3VtZW50cyBwYXNzZWQgdG8gW1thZGRSb3ddXSBvciBbW0Nvbm5lY3Rpb24uZXhlY0J1bGtMb2FkXV0sIHRoZW4geW91IGNhbiB1c2UgdGhpcyBvcHRpb24gdG8gc3BlY2lmeSB0aGUgcHJvcGVydHkgbmFtZS5cbiAgICogQHBhcmFtIHByZWNpc2lvbiBGb3IgTnVtZXJpYywgRGVjaW1hbC5cbiAgICogQHBhcmFtIHNjYWxlIEZvciBOdW1lcmljLCBEZWNpbWFsLCBUaW1lLCBEYXRlVGltZTIsIERhdGVUaW1lT2Zmc2V0LlxuICAqL1xuICBhZGRDb2x1bW4obmFtZTogc3RyaW5nLCB0eXBlOiBEYXRhVHlwZSwgeyBvdXRwdXQgPSBmYWxzZSwgbGVuZ3RoLCBwcmVjaXNpb24sIHNjYWxlLCBvYmpOYW1lID0gbmFtZSwgbnVsbGFibGUgPSB0cnVlIH06IENvbHVtbk9wdGlvbnMpIHtcbiAgICBpZiAodGhpcy5maXJzdFJvd1dyaXR0ZW4pIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignQ29sdW1ucyBjYW5ub3QgYmUgYWRkZWQgdG8gYnVsayBpbnNlcnQgYWZ0ZXIgdGhlIGZpcnN0IHJvdyBoYXMgYmVlbiB3cml0dGVuLicpO1xuICAgIH1cbiAgICBpZiAodGhpcy5leGVjdXRpb25TdGFydGVkKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0NvbHVtbnMgY2Fubm90IGJlIGFkZGVkIHRvIGJ1bGsgaW5zZXJ0IGFmdGVyIGV4ZWN1dGlvbiBoYXMgc3RhcnRlZC4nKTtcbiAgICB9XG5cbiAgICBjb25zdCBjb2x1bW46IENvbHVtbiA9IHtcbiAgICAgIHR5cGU6IHR5cGUsXG4gICAgICBuYW1lOiBuYW1lLFxuICAgICAgdmFsdWU6IG51bGwsXG4gICAgICBvdXRwdXQ6IG91dHB1dCxcbiAgICAgIGxlbmd0aDogbGVuZ3RoLFxuICAgICAgcHJlY2lzaW9uOiBwcmVjaXNpb24sXG4gICAgICBzY2FsZTogc2NhbGUsXG4gICAgICBvYmpOYW1lOiBvYmpOYW1lLFxuICAgICAgbnVsbGFibGU6IG51bGxhYmxlLFxuICAgICAgY29sbGF0aW9uOiB0aGlzLmNvbGxhdGlvblxuICAgIH07XG5cbiAgICBpZiAoKHR5cGUuaWQgJiAweDMwKSA9PT0gMHgyMCkge1xuICAgICAgaWYgKGNvbHVtbi5sZW5ndGggPT0gbnVsbCAmJiB0eXBlLnJlc29sdmVMZW5ndGgpIHtcbiAgICAgICAgY29sdW1uLmxlbmd0aCA9IHR5cGUucmVzb2x2ZUxlbmd0aChjb2x1bW4pO1xuICAgICAgfVxuICAgIH1cblxuICAgIGlmICh0eXBlLnJlc29sdmVQcmVjaXNpb24gJiYgY29sdW1uLnByZWNpc2lvbiA9PSBudWxsKSB7XG4gICAgICBjb2x1bW4ucHJlY2lzaW9uID0gdHlwZS5yZXNvbHZlUHJlY2lzaW9uKGNvbHVtbik7XG4gICAgfVxuXG4gICAgaWYgKHR5cGUucmVzb2x2ZVNjYWxlICYmIGNvbHVtbi5zY2FsZSA9PSBudWxsKSB7XG4gICAgICBjb2x1bW4uc2NhbGUgPSB0eXBlLnJlc29sdmVTY2FsZShjb2x1bW4pO1xuICAgIH1cblxuICAgIHRoaXMuY29sdW1ucy5wdXNoKGNvbHVtbik7XG5cbiAgICB0aGlzLmNvbHVtbnNCeU5hbWVbbmFtZV0gPSBjb2x1bW47XG4gIH1cblxuICAvKipcbiAgICogQHByaXZhdGVcbiAgICovXG4gIGdldE9wdGlvbnNTcWwoKSB7XG4gICAgY29uc3QgYWRkT3B0aW9ucyA9IFtdO1xuXG4gICAgaWYgKHRoaXMuYnVsa09wdGlvbnMuY2hlY2tDb25zdHJhaW50cykge1xuICAgICAgYWRkT3B0aW9ucy5wdXNoKCdDSEVDS19DT05TVFJBSU5UUycpO1xuICAgIH1cblxuICAgIGlmICh0aGlzLmJ1bGtPcHRpb25zLmZpcmVUcmlnZ2Vycykge1xuICAgICAgYWRkT3B0aW9ucy5wdXNoKCdGSVJFX1RSSUdHRVJTJyk7XG4gICAgfVxuXG4gICAgaWYgKHRoaXMuYnVsa09wdGlvbnMua2VlcE51bGxzKSB7XG4gICAgICBhZGRPcHRpb25zLnB1c2goJ0tFRVBfTlVMTFMnKTtcbiAgICB9XG5cbiAgICBpZiAodGhpcy5idWxrT3B0aW9ucy5sb2NrVGFibGUpIHtcbiAgICAgIGFkZE9wdGlvbnMucHVzaCgnVEFCTE9DSycpO1xuICAgIH1cblxuICAgIGlmICh0aGlzLmJ1bGtPcHRpb25zLm9yZGVyKSB7XG4gICAgICBjb25zdCBvcmRlckNvbHVtbnMgPSBbXTtcblxuICAgICAgZm9yIChjb25zdCBbY29sdW1uLCBkaXJlY3Rpb25dIG9mIE9iamVjdC5lbnRyaWVzKHRoaXMuYnVsa09wdGlvbnMub3JkZXIpKSB7XG4gICAgICAgIG9yZGVyQ29sdW1ucy5wdXNoKGAke2NvbHVtbn0gJHtkaXJlY3Rpb259YCk7XG4gICAgICB9XG5cbiAgICAgIGlmIChvcmRlckNvbHVtbnMubGVuZ3RoKSB7XG4gICAgICAgIGFkZE9wdGlvbnMucHVzaChgT1JERVIgKCR7b3JkZXJDb2x1bW5zLmpvaW4oJywgJyl9KWApO1xuICAgICAgfVxuICAgIH1cblxuICAgIGlmIChhZGRPcHRpb25zLmxlbmd0aCA+IDApIHtcbiAgICAgIHJldHVybiBgIFdJVEggKCR7YWRkT3B0aW9ucy5qb2luKCcsJyl9KWA7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJldHVybiAnJztcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogQHByaXZhdGVcbiAgICovXG4gIGdldEJ1bGtJbnNlcnRTcWwoKSB7XG4gICAgbGV0IHNxbCA9ICdpbnNlcnQgYnVsayAnICsgdGhpcy50YWJsZSArICcoJztcbiAgICBmb3IgKGxldCBpID0gMCwgbGVuID0gdGhpcy5jb2x1bW5zLmxlbmd0aDsgaSA8IGxlbjsgaSsrKSB7XG4gICAgICBjb25zdCBjID0gdGhpcy5jb2x1bW5zW2ldO1xuICAgICAgaWYgKGkgIT09IDApIHtcbiAgICAgICAgc3FsICs9ICcsICc7XG4gICAgICB9XG4gICAgICBzcWwgKz0gJ1snICsgYy5uYW1lICsgJ10gJyArIChjLnR5cGUuZGVjbGFyYXRpb24oYykpO1xuICAgIH1cbiAgICBzcWwgKz0gJyknO1xuXG4gICAgc3FsICs9IHRoaXMuZ2V0T3B0aW9uc1NxbCgpO1xuICAgIHJldHVybiBzcWw7XG4gIH1cblxuICAvKipcbiAgICogVGhpcyBpcyBzaW1wbHkgYSBoZWxwZXIgdXRpbGl0eSBmdW5jdGlvbiB3aGljaCByZXR1cm5zIGEgYENSRUFURSBUQUJMRSBTUUxgIHN0YXRlbWVudCBiYXNlZCBvbiB0aGUgY29sdW1ucyBhZGRlZCB0byB0aGUgYnVsa0xvYWQgb2JqZWN0LlxuICAgKiBUaGlzIG1heSBiZSBwYXJ0aWN1bGFybHkgaGFuZHkgd2hlbiB5b3Ugd2FudCB0byBpbnNlcnQgaW50byBhIHRlbXBvcmFyeSB0YWJsZSAoYSB0YWJsZSB3aGljaCBzdGFydHMgd2l0aCBgI2ApLlxuICAgKlxuICAgKiBgYGBqc1xuICAgKiB2YXIgc3FsID0gYnVsa0xvYWQuZ2V0VGFibGVDcmVhdGlvblNxbCgpO1xuICAgKiBgYGBcbiAgICpcbiAgICogQSBzaWRlIG5vdGUgb24gYnVsayBpbnNlcnRpbmcgaW50byB0ZW1wb3JhcnkgdGFibGVzOiBpZiB5b3Ugd2FudCB0byBhY2Nlc3MgYSBsb2NhbCB0ZW1wb3JhcnkgdGFibGUgYWZ0ZXIgZXhlY3V0aW5nIHRoZSBidWxrIGxvYWQsXG4gICAqIHlvdSdsbCBuZWVkIHRvIHVzZSB0aGUgc2FtZSBjb25uZWN0aW9uIGFuZCBleGVjdXRlIHlvdXIgcmVxdWVzdHMgdXNpbmcgW1tDb25uZWN0aW9uLmV4ZWNTcWxCYXRjaF1dIGluc3RlYWQgb2YgW1tDb25uZWN0aW9uLmV4ZWNTcWxdXVxuICAgKi9cbiAgZ2V0VGFibGVDcmVhdGlvblNxbCgpIHtcbiAgICBsZXQgc3FsID0gJ0NSRUFURSBUQUJMRSAnICsgdGhpcy50YWJsZSArICcoXFxuJztcbiAgICBmb3IgKGxldCBpID0gMCwgbGVuID0gdGhpcy5jb2x1bW5zLmxlbmd0aDsgaSA8IGxlbjsgaSsrKSB7XG4gICAgICBjb25zdCBjID0gdGhpcy5jb2x1bW5zW2ldO1xuICAgICAgaWYgKGkgIT09IDApIHtcbiAgICAgICAgc3FsICs9ICcsXFxuJztcbiAgICAgIH1cbiAgICAgIHNxbCArPSAnWycgKyBjLm5hbWUgKyAnXSAnICsgKGMudHlwZS5kZWNsYXJhdGlvbihjKSk7XG4gICAgICBpZiAoYy5udWxsYWJsZSAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHNxbCArPSAnICcgKyAoYy5udWxsYWJsZSA/ICdOVUxMJyA6ICdOT1QgTlVMTCcpO1xuICAgICAgfVxuICAgIH1cbiAgICBzcWwgKz0gJ1xcbiknO1xuICAgIHJldHVybiBzcWw7XG4gIH1cblxuICAvKipcbiAgICogQHByaXZhdGVcbiAgICovXG4gIGdldENvbE1ldGFEYXRhKCkge1xuICAgIGNvbnN0IHRCdWYgPSBuZXcgV3JpdGFibGVUcmFja2luZ0J1ZmZlcigxMDAsIG51bGwsIHRydWUpO1xuICAgIC8vIFRva2VuVHlwZVxuICAgIHRCdWYud3JpdGVVSW50OChUT0tFTl9UWVBFLkNPTE1FVEFEQVRBKTtcbiAgICAvLyBDb3VudFxuICAgIHRCdWYud3JpdGVVSW50MTZMRSh0aGlzLmNvbHVtbnMubGVuZ3RoKTtcblxuICAgIGZvciAobGV0IGogPSAwLCBsZW4gPSB0aGlzLmNvbHVtbnMubGVuZ3RoOyBqIDwgbGVuOyBqKyspIHtcbiAgICAgIGNvbnN0IGMgPSB0aGlzLmNvbHVtbnNbal07XG4gICAgICAvLyBVc2VyVHlwZVxuICAgICAgaWYgKHRoaXMub3B0aW9ucy50ZHNWZXJzaW9uIDwgJzdfMicpIHtcbiAgICAgICAgdEJ1Zi53cml0ZVVJbnQxNkxFKDApO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdEJ1Zi53cml0ZVVJbnQzMkxFKDApO1xuICAgICAgfVxuXG4gICAgICAvLyBGbGFnc1xuICAgICAgbGV0IGZsYWdzID0gRkxBR1MudXBkYXRlYWJsZVJlYWRXcml0ZTtcbiAgICAgIGlmIChjLm51bGxhYmxlKSB7XG4gICAgICAgIGZsYWdzIHw9IEZMQUdTLm51bGxhYmxlO1xuICAgICAgfSBlbHNlIGlmIChjLm51bGxhYmxlID09PSB1bmRlZmluZWQgJiYgdGhpcy5vcHRpb25zLnRkc1ZlcnNpb24gPj0gJzdfMicpIHtcbiAgICAgICAgZmxhZ3MgfD0gRkxBR1MubnVsbGFibGVVbmtub3duO1xuICAgICAgfVxuICAgICAgdEJ1Zi53cml0ZVVJbnQxNkxFKGZsYWdzKTtcblxuICAgICAgLy8gVFlQRV9JTkZPXG4gICAgICB0QnVmLndyaXRlQnVmZmVyKGMudHlwZS5nZW5lcmF0ZVR5cGVJbmZvKGMsIHRoaXMub3B0aW9ucykpO1xuXG4gICAgICAvLyBUYWJsZU5hbWVcbiAgICAgIGlmIChjLnR5cGUuaGFzVGFibGVOYW1lKSB7XG4gICAgICAgIHRCdWYud3JpdGVVc1ZhcmNoYXIodGhpcy50YWJsZSwgJ3VjczInKTtcbiAgICAgIH1cblxuICAgICAgLy8gQ29sTmFtZVxuICAgICAgdEJ1Zi53cml0ZUJWYXJjaGFyKGMubmFtZSwgJ3VjczInKTtcbiAgICB9XG4gICAgcmV0dXJuIHRCdWYuZGF0YTtcbiAgfVxuXG4gIC8qKlxuICAgKiBTZXRzIGEgdGltZW91dCBmb3IgdGhpcyBidWxrIGxvYWQuXG4gICAqXG4gICAqIGBgYGpzXG4gICAqIGJ1bGtMb2FkLnNldFRpbWVvdXQodGltZW91dCk7XG4gICAqIGBgYFxuICAgKlxuICAgKiBAcGFyYW0gdGltZW91dCBUaGUgbnVtYmVyIG9mIG1pbGxpc2Vjb25kcyBiZWZvcmUgdGhlIGJ1bGsgbG9hZCBpcyBjb25zaWRlcmVkIGZhaWxlZCwgb3IgMCBmb3Igbm8gdGltZW91dC5cbiAgICogICBXaGVuIG5vIHRpbWVvdXQgaXMgc2V0IGZvciB0aGUgYnVsayBsb2FkLCB0aGUgW1tDb25uZWN0aW9uT3B0aW9ucy5yZXF1ZXN0VGltZW91dF1dIG9mIHRoZSBDb25uZWN0aW9uIGlzIHVzZWQuXG4gICAqL1xuICBzZXRUaW1lb3V0KHRpbWVvdXQ/OiBudW1iZXIpIHtcbiAgICB0aGlzLnRpbWVvdXQgPSB0aW1lb3V0O1xuICB9XG5cbiAgLyoqXG4gICAqIEBwcml2YXRlXG4gICAqL1xuICBjcmVhdGVEb25lVG9rZW4oKSB7XG4gICAgLy8gSXQgbWlnaHQgYmUgbmljZSB0byBtYWtlIERvbmVUb2tlbiBhIGNsYXNzIGlmIGFueXRoaW5nIG5lZWRzIHRvIGNyZWF0ZSB0aGVtLCBidXQgZm9yIG5vdywganVzdCBkbyBpdCBoZXJlXG4gICAgY29uc3QgdEJ1ZiA9IG5ldyBXcml0YWJsZVRyYWNraW5nQnVmZmVyKHRoaXMub3B0aW9ucy50ZHNWZXJzaW9uIDwgJzdfMicgPyA5IDogMTMpO1xuICAgIHRCdWYud3JpdGVVSW50OChUT0tFTl9UWVBFLkRPTkUpO1xuICAgIGNvbnN0IHN0YXR1cyA9IERPTkVfU1RBVFVTLkZJTkFMO1xuICAgIHRCdWYud3JpdGVVSW50MTZMRShzdGF0dXMpO1xuICAgIHRCdWYud3JpdGVVSW50MTZMRSgwKTsgLy8gQ3VyQ21kIChURFMgaWdub3JlcyB0aGlzKVxuICAgIHRCdWYud3JpdGVVSW50MzJMRSgwKTsgLy8gcm93IGNvdW50IC0gZG9lc24ndCByZWFsbHkgbWF0dGVyXG4gICAgaWYgKHRoaXMub3B0aW9ucy50ZHNWZXJzaW9uID49ICc3XzInKSB7XG4gICAgICB0QnVmLndyaXRlVUludDMyTEUoMCk7IC8vIHJvdyBjb3VudCBpcyA2NCBiaXRzIGluID49IFREUyA3LjJcbiAgICB9XG4gICAgcmV0dXJuIHRCdWYuZGF0YTtcbiAgfVxuXG4gIC8qKlxuICAgKiBAcHJpdmF0ZVxuICAgKi9cbiAgY2FuY2VsKCkge1xuICAgIGlmICh0aGlzLmNhbmNlbGVkKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgdGhpcy5jYW5jZWxlZCA9IHRydWU7XG4gICAgdGhpcy5lbWl0KCdjYW5jZWwnKTtcbiAgfVxufVxuXG5leHBvcnQgZGVmYXVsdCBCdWxrTG9hZDtcbm1vZHVsZS5leHBvcnRzID0gQnVsa0xvYWQ7XG4iXSwibWFwcGluZ3MiOiI7Ozs7OztBQUFBLElBQUFBLE9BQUEsR0FBQUMsT0FBQTtBQUNBLElBQUFDLHVCQUFBLEdBQUFDLHNCQUFBLENBQUFGLE9BQUE7QUFHQSxJQUFBRyxPQUFBLEdBQUFILE9BQUE7QUFDQSxJQUFBSSxNQUFBLEdBQUFKLE9BQUE7QUFBbUQsU0FBQUUsdUJBQUFHLENBQUEsV0FBQUEsQ0FBQSxJQUFBQSxDQUFBLENBQUFDLFVBQUEsR0FBQUQsQ0FBQSxLQUFBRSxPQUFBLEVBQUFGLENBQUE7QUFLbkQ7QUFDQTtBQUNBO0FBQ0EsTUFBTUcsS0FBSyxHQUFHO0VBQ1pDLFFBQVEsRUFBRSxDQUFDLElBQUksQ0FBQztFQUNoQkMsT0FBTyxFQUFFLENBQUMsSUFBSSxDQUFDO0VBQ2ZDLG1CQUFtQixFQUFFLENBQUMsSUFBSSxDQUFDO0VBQzNCQyxpQkFBaUIsRUFBRSxDQUFDLElBQUksQ0FBQztFQUN6QkMsUUFBUSxFQUFFLENBQUMsSUFBSSxDQUFDO0VBQ2hCQyxRQUFRLEVBQUUsQ0FBQyxJQUFJLENBQUM7RUFBRTtFQUNsQkMsZUFBZSxFQUFFLENBQUMsSUFBSSxDQUFDO0VBQUU7RUFDekJDLGVBQWUsRUFBRSxDQUFDLElBQUksRUFBRTtFQUFFO0VBQzFCQyxNQUFNLEVBQUUsQ0FBQyxJQUFJLEVBQUU7RUFBRTtFQUNqQkMsR0FBRyxFQUFFLENBQUMsSUFBSSxFQUFFO0VBQUU7RUFDZEMsZUFBZSxFQUFFLENBQUMsSUFBSSxFQUFFLENBQUM7QUFDM0IsQ0FBQzs7QUFFRDtBQUNBO0FBQ0E7QUFDQSxNQUFNQyxXQUFXLEdB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