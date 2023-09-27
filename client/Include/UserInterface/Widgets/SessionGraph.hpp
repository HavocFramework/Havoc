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
    Node*        Parent       = nullptr; // Pointer to the parent node of the current node. Null for the root.
    Node*        Thread       = nullptr; // For extreme left or right nodes, used to provide a successor node in a contour.
    Node*        Ancestor     = this;    // During the tree layout, it points to the node's ancestor that is used to determine how far apart different subtrees should be.
    bool         Disconnected = false;
    double       Prelim       = 0;       // Preliminary y-coordinate calculated during the first tree traversal.
    double       Modifier     = 0;       // Amount to adjust a node's y-coordinate, based on the positions of its descendants.
    double       Shift        = 0;       // Amount to move subtrees apart to avoid overlaps.
    double       Change       = 0;       // Rate of change in shift amount, used to evenly distribute shifts among siblings.
    
    std::vector<Node*> Children = std::vector<Node*>();

    HavocNamespace::Util::SessionItem Session;

public:
    Node( NodeItemType NodeType, QString NodeLabel, GraphWidget* graphWidget );

    void appendChild( Node* child );
    void removeChild( Node* child );

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
        class Node*   Node;
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
    const double X_SEP = 220; // Horizontal separation between levels of the tree
    const double Y_SEP = 120; // Vertical separation between sibling nodes

    void initNode(Node* v);
    void layout(Node* T);
    void firstWalk(Node* v);
    void apportion(Node* v, Node*& defaultAncestor);
    void moveSubtree(Node* wm, Node* wp, double shift);
    Node* nextLeft(Node* v);
    Node* nextRight(Node* v);
    Node* ancestor(Node* vim, Node* v, Node*& defaultAncestor);
    void executeShifts(Node* v);
    void secondWalk(Node* v, double m, double depth);
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
