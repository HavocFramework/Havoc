#ifndef HAVOC_SESSIONGRAPH_HPP
#define HAVOC_SESSIONGRAPH_HPP

#include <global.hpp>

#include <QGraphicsItem>
#include <QGraphicsView>
#include <QRect>

class Node;
class GraphWidget;
class Edge;

enum class NodeItemType {
    Nothing  = 0,
    MainNode = 1,
    Session  = 2
};

class Node : public QGraphicsItem
{
    QRectF  NodePainterSize = QRectF();
    QString NodeLabel       = QString();

public:
    QString      NodeID       = QString();
    NodeItemType NodeType     = NodeItemType::Nothing;
    Edge*        NodeEdge     = nullptr;
    bool         Disconnected = false;

    HavocNamespace::Util::SessionItem Session;

public:
    Node( NodeItemType NodeType, QString NodeLabel, GraphWidget* graphWidget );

    void addEdge( Edge* edge );
    QVector<Edge*> edges() const;

    enum { Type = UserType + 1 };
    int type() const override { return Type; }

    void calculateForces();
    bool advancePosition();

    void contextMenuEvent(QGraphicsSceneContextMenuEvent *event) override;

    QRectF boundingRect() const override;
    QPainterPath shape() const override;

    void paint( QPainter* painter, const QStyleOptionGraphicsItem* option, QWidget* widget ) override;

protected:
    QVariant itemChange( GraphicsItemChange change, const QVariant& value ) override;

    void mousePressEvent( QGraphicsSceneMouseEvent* event ) override;
    void mouseReleaseEvent( QGraphicsSceneMouseEvent* event ) override;
    void mouseMoveEvent( QGraphicsSceneMouseEvent* event ) override;

private:
    QVector<Edge*>  edgeList;
    QPointF         newPos;
    GraphWidget*    graph;
};

class GraphWidget : public QGraphicsView
{
Q_OBJECT
    typedef struct
    {
        QString Name;
        Node*   Node;
    } Member;

    QGraphicsScene*      GraphScene = nullptr;
    Member*              MainNode   = nullptr;
    std::vector<Member*> NodeList   = std::vector<Member*>();

public:
    GraphWidget( QWidget* parent = nullptr );

    void itemMoved();

    Node* GraphNodeAdd( HavocNamespace::Util::SessionItem Session );
    void  GraphNodeRemove( HavocNamespace::Util::SessionItem Session );
    Node* GraphNodeGet( QString AgentID );

    void  GraphPivotNodeAdd( QString AgentID, HavocNamespace::Util::SessionItem Session );
    void  GraphPivotNodeDisconnect( QString AgentID );
    void  GraphPivotNodeReconnect( QString ParentAgentID, QString ChildAgentID );

public slots:
    void shuffle();
    void zoomIn();
    void zoomOut();

protected:
    void keyPressEvent( QKeyEvent* event ) override;
    void timerEvent( QTimerEvent* event ) override;
    void resizeEvent( QResizeEvent* event ) override;

#if QT_CONFIG( wheelevent )
    void wheelEvent( QWheelEvent* event ) override;
#endif

    void drawBackground( QPainter* painter, const QRectF& rect ) override;
    void scaleView( qreal scaleFactor );

private:
    int timerId = 0;
    Node* centerNode;
};

class Edge : public QGraphicsItem
{
public:
    Node* source = nullptr;
    Node* dest   = nullptr;

    Edge( Node* sourceNode, Node* destNode, QColor Color );

    Node* sourceNode() const;
    Node* destNode() const;

    void adjust();
    void Color( QColor color );

    enum { Type = UserType + 2 };
    int type() const override { return Type; }

protected:
    QRectF boundingRect() const override;
    void paint( QPainter* painter, const QStyleOptionGraphicsItem* option, QWidget* widget ) override;

private:
    QColor  color       = QColor();
    QPointF sourcePoint = QPointF();
    QPointF destPoint   = QPointF();
    qreal   arrowSize   = 10;
};

#endif
